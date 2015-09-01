/****************************
* 2011.1     Miao Yu     Implement EPT for Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#include <arch/vmx/ept.h>
#include <arch/vmx/vmx.h>
#include <arch/mtrr.h>
#include <vis/types.h>
#include <vis/spinlock.h>
#include <vis/arch.h>

struct page_info* ept_pml4_page;
struct arch_phy* arch;

static NTSTATUS NTAPI ept_update_table (
	PVOID PageTable,
	UCHAR PageTableLevel,
	gfn_t gfn,
  	mfn_t mfn,
  	ULONG32 p2m_type,
	BOOLEAN bLargePage,
	P2M_UPDATE_TYPE op_type
)
{
  	ULONG64 PageTableOffset, GlobalOffset;
  	ULONG64 GlobalOffset1, GlobalOffset2, GlobalOffset3, GlobalOffset4;
	gvaddr_t LowerPageTableGuestVA;
  	struct page_info *LowerPageTable;
  	PHYSICAL_ADDRESS LowerPageTablePA;
	gfn_t LowerPageTableGfn;
  	NTSTATUS Status;
  	PHYSICAL_ADDRESS PagePA, l1, l2, l3;
  	ept_entry_t ept_entry = {0};
	
  	// get the offset in the specified page table level
  	PageTableOffset = (((ULONG64) gfn & (((ULONG64) 1) << (PageTableLevel * EPT_TABLE_ORDER))
                      - 1) >> (((ULONG64) PageTableLevel - 1) * EPT_TABLE_ORDER));

  	if ((PageTableLevel == 1) || (bLargePage && (PageTableLevel == 2))) {
		// last level page table
		ept_entry.epte = ((PULONG64) PageTable)[PageTableOffset];
		
		if(op_type & P2M_UPDATE_MT)
		{
			ept_entry.r = (p2m_type & P2M_READABLE) ? 1 : 0;
			ept_entry.w = (p2m_type & P2M_WRITABLE) ? 1 : 0;
			ept_entry.x = (p2m_type & P2M_EXECUTABLE) ? 1 : 0;
		}

		if(op_type & P2M_UPDATE_REMAININGS)
		{
			ept_entry.emt = MTRR_TYPE_WRBACK;
			ept_entry.ipat = 0;
			ept_entry.sp_avail = 0;
		}
		
		if(op_type & P2M_UPDATE_MFN)
			ept_entry.mfn = mfn;
	
    	if (bLargePage)
    	{
    		assert((PageTableLevel == 2), ("LargePage at the 4th ept page table?"));
			if(op_type & P2M_UPDATE_REMAININGS)
      			ept_entry.sp_avail = 1;
    	}
		((PULONG64) PageTable)[PageTableOffset] = ept_entry.epte;
    	return STATUS_SUCCESS;
  	}
	ept_entry.epte = ((PULONG64) PageTable)[PageTableOffset];
	LowerPageTableGfn = (gfn_t)ept_entry.mfn;
  	
  	if (!LowerPageTableGfn) {
		/* we have not allocated this mid level page table before */

    	Status = MmFindPageByGPA (gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);
    	if (!NT_SUCCESS (Status)) {
      		LowerPageTableGuestVA = MmAllocatePages(1, (gpaddr_t*)&LowerPageTablePA.QuadPart, TRUE);
      		if (!LowerPageTableGuestVA)
      		{
      			panic(("ept_update_table(): no memory"));
        		return STATUS_INSUFFICIENT_RESOURCES;
      		}
      		RtlZeroMemory ((PVOID)LowerPageTableGuestVA, PAGE_SIZE);
		#if defined(_X86_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.LowPart);
		#elif defined(_X64_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.QuadPart);
		#endif
    	} else {
      		LowerPageTableGfn = LowerPageTable->gfn;
      		LowerPageTableGuestVA = LowerPageTable->gvaddr;
    	}
		assert((LowerPageTableGfn), ("LowerPageTableGfn has an invalid value"));
		
		ept_entry.r = ept_entry.w = ept_entry.x = 1;
		ept_entry.emt = 0;
		ept_entry.ipat = 0;
		ept_entry.sp_avail = 0;
		ept_entry.mfn = LowerPageTableGfn;
	    ((PULONG64) PageTable)[PageTableOffset] = ept_entry.epte;

  	} else {
		/* we have allocated this mid level page table before */
		//Status = MmFindPageByGPA (LowerPageTablePA, &LowerPageTable);
	    Status = MmFindPageByGPA (gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);
	    
	    if (!NT_SUCCESS (Status)) {
	      	LowerPageTablePA.QuadPart = ((PULONG64) PageTable)[PageTableOffset];
	      	if ((PageTableLevel == 2) && (LowerPageTablePA.QuadPart & P_LARGE)) {
	        	dprint(PRINT_ERROR,
					("ept_update_table(): Found large PDE, data 0x%p\n", LowerPageTablePA.QuadPart));
	        	return STATUS_SUCCESS;

	      	} else {
	        	dprint(PRINT_ERROR,
	          		("ept_update_table(): Failed to find lower page table (pl%d) guest VA, data 0x%p, status 0x%08X\n",
	           			PageTableLevel - 1, LowerPageTablePA.QuadPart, Status));
	       	  	return Status;
	      	}
	    }

	    LowerPageTableGuestVA = LowerPageTable->gvaddr;
  	}

  return ept_update_table ((PVOID)LowerPageTableGuestVA, PageTableLevel - 1, gfn, mfn, 
  				p2m_type, bLargePage, op_type);
}

static NTSTATUS NTAPI ept_update_identity_table (
	PVOID PageTable,
	UCHAR PageTableLevel,
	gfn_t gfn,
	ULONG32 p2m_type,
	BOOLEAN bLargePage,
	P2M_UPDATE_TYPE op_type
)
{
  	ULONG64 PageTableOffset, GlobalOffset;
  	ULONG64 GlobalOffset1, GlobalOffset2, GlobalOffset3, GlobalOffset4;
	gvaddr_t LowerPageTableGuestVA;
  	struct page_info *LowerPageTable;
  	PHYSICAL_ADDRESS LowerPageTablePA;
	gfn_t LowerPageTableGfn;
  	NTSTATUS Status;
  	PHYSICAL_ADDRESS PagePA, l1, l2, l3;
  	ept_entry_t ept_entry = {0};

	assert(((gfn & (EPT_EACHTABLE_ENTRIES - 1))==0), 
			("ept_update_identity_table(): gfn is not the integer times of PTE, \
			can't map gfn in the batched way."));
  	// get the offset in the specified page table level
  	PageTableOffset = (((ULONG64) gfn & (((ULONG64) 1) << (PageTableLevel * EPT_TABLE_ORDER))
                      - 1) >> (((ULONG64) PageTableLevel - 1) * EPT_TABLE_ORDER));

  	if ((PageTableLevel == 1) || (bLargePage && (PageTableLevel == 2))) {
		// last level page table
		ULONG i = 0;

		for( i = 0; i < EPT_EACHTABLE_ENTRIES; i++)
		{
			ept_entry.epte = ((PULONG64) PageTable)[PageTableOffset + i];
		
			if(op_type & P2M_UPDATE_MT)
			{
				ept_entry.r = (p2m_type & P2M_READABLE) ? 1 : 0;
				ept_entry.w = (p2m_type & P2M_WRITABLE) ? 1 : 0;
				ept_entry.x = (p2m_type & P2M_EXECUTABLE) ? 1 : 0;
			}
			//ept_entry.r = ept_entry.w = ept_entry.x = 1;
			if(op_type & P2M_UPDATE_REMAININGS)
			{
				ept_entry.emt = MTRR_TYPE_WRBACK;
				ept_entry.ipat = 0;
				ept_entry.sp_avail = 0;
			}
			
			if(op_type & P2M_UPDATE_MFN)
				ept_entry.mfn = gfn + i;
		
	    	if (bLargePage)
	    	{
	    		assert((PageTableLevel == 2), ("LargePage at the 4th ept page table?"));
				if(op_type & P2M_UPDATE_REMAININGS)
	      			ept_entry.sp_avail = 1;
	    	}
			((PULONG64) PageTable)[PageTableOffset + i] = ept_entry.epte;
		}
    	return STATUS_SUCCESS;
  	}
	ept_entry.epte = ((PULONG64) PageTable)[PageTableOffset];
	LowerPageTableGfn = (gfn_t)ept_entry.mfn;
  	
  	if (!LowerPageTableGfn) {
		/* we have not allocated this mid level page table before */

    	Status = MmFindPageByGPA (gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);
    	if (!NT_SUCCESS (Status)) {
      		//LowerPageTableGuestVA = ExAllocatePoolWithTag (NonPagedPool, PAGE_SIZE, ITL_TAG);
      		LowerPageTableGuestVA = MmAllocatePages(1, (gpaddr_t*)&LowerPageTablePA.QuadPart, TRUE);
      		if (!LowerPageTableGuestVA)
      		{
      			panic(("ept_update_table(): no memory"));
        		return STATUS_INSUFFICIENT_RESOURCES;
      		}
      		RtlZeroMemory ((PVOID)LowerPageTableGuestVA, PAGE_SIZE);
		#if defined(_X86_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.LowPart);
		#elif defined(_X64_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.QuadPart);
		#endif
    	} else {
      LowerPageTableGfn = LowerPageTable->gfn;
      LowerPageTableGuestVA = LowerPageTable->gvaddr;
    }

	assert((LowerPageTableGfn), ("LowerPageTableGfn has an invalid value"));
	
	ept_entry.r = ept_entry.w = ept_entry.x = 1;
	ept_entry.emt = 0;
	ept_entry.ipat = 0;
	ept_entry.sp_avail = 0;
	ept_entry.mfn = LowerPageTableGfn;
    ((PULONG64) PageTable)[PageTableOffset] = ept_entry.epte;
  	} else {
		/* we have allocated this mid level page table before */
	    Status = MmFindPageByGPA (gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);
	    
	    if (!NT_SUCCESS (Status)) {
	      	LowerPageTablePA.QuadPart = ((PULONG64) PageTable)[PageTableOffset];
	      	if ((PageTableLevel == 2) && (LowerPageTablePA.QuadPart & P_LARGE)) {
	        	dprint(PRINT_ERROR,
					("ept_update_table(): Found large PDE, data 0x%p\n", LowerPageTablePA.QuadPart));
	        	return STATUS_SUCCESS;

	      	} else {
	        	dprint(PRINT_ERROR,
	          		("ept_update_table(): Failed to find lower page table (pl%d) guest VA, data 0x%p, status 0x%08X\n",
	           			PageTableLevel - 1, LowerPageTablePA.QuadPart, Status));
	       	  	return Status;
	      	}
	    }

	    LowerPageTableGuestVA = LowerPageTable->gvaddr;
  	}

  return ept_update_identity_table ((PVOID)LowerPageTableGuestVA, PageTableLevel - 1, gfn, p2m_type, 
  				bLargePage, op_type);
}

static VOID NTAPI ept_tlb_flush(void)
{
	ULONG64 eptp = arch->hvm.ept_ctl.eptp;
	struct {
        ULONG64 eptp, gpa;
    } operand = {eptp, 0};

	assert((eptp),("ept_tlb_flush():EPTP error"));
	//DbgPrint("eptp value:0x%llx\n", eptp);
	__vmx_invept(1, (ULONG32)&operand);
}

static VOID NTAPI ept_vpid_flush(void)
{
	struct {
        ULONG64 vpid:16;
        ULONG64 rsvd:48;
        ULONG64 gva;
    }  operand = {0, 0, 0};

	__vmx_invvpid(2, (ULONG32)&operand);
}

static NTSTATUS NTAPI ept_create_mapping(
  	gfn_t gfn,
  	mfn_t mfn,
  	ULONG32 p2m_type,
  	BOOLEAN bLargePage
)
{
	NTSTATUS status;

	if(arch->p2m.holder != KeGetCurrentProcessorNumber())
	{
		spin_lock_acquire(&arch->p2m.lock);
		arch->p2m.holder = KeGetCurrentProcessorNumber();
	}
	
	status = ept_update_table ((PVOID)ept_pml4_page->gvaddr, 4, gfn, mfn, p2m_type, 
		bLargePage, P2M_UPDATE_ALL);
	
	if(arch->p2m.holder == KeGetCurrentProcessorNumber())
	{
		spin_lock_release(&arch->p2m.lock);
		arch->p2m.holder = NO_HOLDER;
	}

	arch->p2m.need_flush = TRUE;
  	return status;
}

static NTSTATUS NTAPI ept_update_mapping(
  gfn_t gfn,
  mfn_t mfn,
  ULONG32 p2m_type,
  BOOLEAN bLargePage,
  P2M_UPDATE_TYPE op_type
)
{
	NTSTATUS status;

	if(arch->p2m.holder != KeGetCurrentProcessorNumber())
	{
		spin_lock_acquire(&arch->p2m.lock);
		arch->p2m.holder = KeGetCurrentProcessorNumber();
	}
	
	status = ept_update_table ((PVOID)ept_pml4_page->gvaddr, 4, gfn, mfn, p2m_type, 
		bLargePage, op_type);
	
	if(arch->p2m.holder == KeGetCurrentProcessorNumber())
	{
		spin_lock_release(&arch->p2m.lock);
		arch->p2m.holder = NO_HOLDER;
	}

	arch->p2m.need_flush = TRUE;
  	return status;
}

static NTSTATUS NTAPI ept_update_all_mapping(ULONG32 p2m_type)
{
	NTSTATUS status;
	gfn_t gfn;

	if(arch->p2m.holder != KeGetCurrentProcessorNumber())
	{
		spin_lock_acquire(&arch->p2m.lock);
		arch->p2m.holder = KeGetCurrentProcessorNumber();
	}
	
	#ifdef _X86_
	//for(gfn = 0x0; gfn<=0xfffff; gfn += EPT_EACHTABLE_ENTRIES)
	for(gfn = 0x0; gfn < (arch->mm.mm_highest_gfn / EPT_EACHTABLE_ENTRIES + 1) * EPT_EACHTABLE_ENTRIES
		; gfn += EPT_EACHTABLE_ENTRIES)
	{
		/* All large pages are split into 4K pages. */
		status = ept_update_identity_table((PVOID)ept_pml4_page->gvaddr, 4, gfn, p2m_type, 
			FALSE, P2M_UPDATE_MT);

		assert((NT_SUCCESS (status)), ("Vis: mm_map_machine_pfns() failed with status 0x%08hX\n", status));
	}
	#endif

	if(arch->p2m.holder == KeGetCurrentProcessorNumber())
	{
		spin_lock_release(&arch->p2m.lock);
		arch->p2m.holder = NO_HOLDER;
	}

	arch->p2m.need_flush = TRUE;
  	return status;
}


/* This is used to map all the available pfns on the current platform */
static NTSTATUS NTAPI ept_create_identity_map(void)
{
	NTSTATUS status;
	gfn_t gfn;

	if(arch->p2m.holder != KeGetCurrentProcessorNumber())
	{
		spin_lock_acquire(&arch->p2m.lock);
		arch->p2m.holder = KeGetCurrentProcessorNumber();
	}
	
	#ifdef _X86_
	for(gfn = 0x0; gfn<=0xfffff; gfn += EPT_EACHTABLE_ENTRIES)
	{
		/* All large pages are split into 4K pages. */
		status = ept_update_identity_table((PVOID)ept_pml4_page->gvaddr, 4, gfn, P2M_FULL_ACCESS, 
			FALSE, P2M_UPDATE_ALL);
		if (!NT_SUCCESS (status))
		{
            dprint(PRINT_ERROR, ("Vis: mm_map_machine_pfns() failed with status 0x%08hX\n", status));
    	}
	}
	#endif

	if(arch->p2m.holder == KeGetCurrentProcessorNumber())
	{
		spin_lock_release(&arch->p2m.lock);
		arch->p2m.holder = NO_HOLDER;
	}

	arch->p2m.need_flush = TRUE;
  	return status;
}

VOID NTAPI ept_init(struct arch_phy* parch)
{
	gpaddr_t ept_pml4_page_paddr = 0;
	gvaddr_t ept_pml4_page_vaddr = 0;
	NTSTATUS status;

	arch = parch;
	spin_lock_init(&arch->p2m.lock);
	
	spin_lock_acquire(&arch->p2m.lock);
	arch->p2m.holder = KeGetCurrentProcessorNumber();

	/* set ept callbacks in p2m */
	arch->p2m.p2m_create_mapping = &ept_create_mapping;
	arch->p2m.p2m_tlb_flush = &ept_tlb_flush;
	arch->p2m.p2m_vpid_flush = &ept_vpid_flush;
	arch->p2m.p2m_create_identity_map = &ept_create_identity_map;
	arch->p2m.p2m_update_mapping = &ept_update_mapping;
	arch->p2m.p2m_update_all_mapping = &ept_update_all_mapping;
	/* allocate ept PML4 page */
	ept_pml4_page_vaddr = MmAllocateContiguousPages(1, &ept_pml4_page_paddr, TRUE);
	status = MmFindPageByGPA (ept_pml4_page_paddr, &ept_pml4_page);
	assert((NT_SUCCESS(status)),("ept_init() failed!"));
	
	arch->p2m.p2m_table = gpaddr_to_gfn(ept_pml4_page_paddr);
	
	/* set epte */
	arch->hvm.ept_ctl.etmt = EPT_DEFAULT_MT;
	arch->hvm.ept_ctl.gaw = EPT_DEFAULT_GAW;
	arch->hvm.ept_ctl.asr = pagetable_get_fn(arch->p2m.p2m_table);

	spin_lock_release(&arch->p2m.lock);
	arch->p2m.holder = NO_HOLDER;

	print("P2M:EPT is enabled\n");
}
