/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

/* This file is much more related to WinXP platform specifically 
     It is REQUIRED to rewrite these functions when migrating to other OSes */
#include <vis/ppt.h>
#include <vis/mm.h>
#include <vis/arch.h>

#ifdef CONFIG_USE_PRIVATE_PAGETABLE

static gpaddr_t ppt_pd_gpaddr;
static gvaddr_t ppt_pd_gvaddr;
struct arch_phy* arch;

static VOID NTAPI ppt_create_mapping (
  gpaddr_t PhysicalAddress,
  gvaddr_t VirtualAddress,
  BOOLEAN bLargePage
);


static VOID NTAPI ppt_update_entries (
  PVOID PageTable,
  UCHAR PageTableLevel,
  gvaddr_t gvaddr,
  gpaddr_t gpaddr,
  BOOLEAN bLargePage
)
{
    ULONG PageTableOffset;
    gvaddr_t LowerPageTableHostVA, LowerPageTableGuestVA;
    struct page_info *LowerPageTable;
	gpaddr_t LowerPageTablePA;
    //PHYSICAL_ADDRESS LowerPageTablePA;
    NTSTATUS Status;
    PHYSICAL_ADDRESS PagePA;

    // get the offset in the specified page table level
    switch (PageTableLevel)
    {
	    case 1:
	        PageTableOffset = PT_LEVEL_OFFSET(gvaddr);
			//PageTableOffset = ((ULONG)gvaddr >> 12) & 0x3ff;
	        break;
	    case 2:
	        PageTableOffset = PD_LEVEL_OFFSET(gvaddr);
			//PageTableOffset = (ULONG)gvaddr >> 22;
	        break;
	    default:
	        panic(("ppt_update_entries():Invalid virtual addr"));
    }

    if ((PageTableLevel == 1) || (bLargePage && (PageTableLevel == 2))) 
    {
        // patch PTE/PDE
        ((PULONG) PageTable)[PageTableOffset] = 
            (ULONG)(gpaddr | /*P_GLOBAL | */ P_WRITABLE | P_PRESENT);

        if (bLargePage)
            ((PULONG) PageTable)[PageTableOffset] |= P_LARGE;

        return;
    }

    // here, must be pde, PageTableLevel == 2
    LowerPageTablePA = 
        ((PULONG)PageTable)[PageTableOffset] & ALIGN_4KPAGE_MASK;
    // get the host pagetable va
    LowerPageTableHostVA =
        ((((gvaddr & PD_MASK) >> 12) << 2) + WIN_PTE_BASE);

    if (!LowerPageTablePA) 
    {
        // the next level page is not in the memory
        Status = MmFindPageByGVA (LowerPageTableHostVA, &LowerPageTable);
        if (!NT_SUCCESS (Status) || gvaddr == LowerPageTableHostVA) 
        {
        	// fail to find the page, then allocate it
        	LowerPageTableGuestVA = MmAllocatePages(1, &LowerPageTablePA, TRUE);

			assert((!LowerPageTableGuestVA), ("ppt_update_entries(): Allocation error"));
        } 
        else 
        {
            // found the page
            LowerPageTablePA = gfn_to_gpaddr(LowerPageTable->gfn);
            LowerPageTableGuestVA = LowerPageTable->gvaddr;
        }

        ((PULONG) PageTable)[PageTableOffset] = 
            (ULONG)(LowerPageTablePA | /*P_GLOBAL | */ P_WRITABLE | P_PRESENT);

        // create mapping
        ppt_create_mapping (LowerPageTablePA, LowerPageTableHostVA, FALSE);

    } 
    else 
    {
        // LowerPageTablePA is not NULL
        Status = MmFindPageByGPA (LowerPageTablePA, &LowerPageTable);
        if (!NT_SUCCESS (Status)) 
        {
            LowerPageTablePA = ((PULONG) PageTable)[PageTableOffset];
            if ((PageTableLevel == 2) && (LowerPageTablePA & P_LARGE)) 
            {
                // found a large page
                dprint (PRINT_INFO, (
                    "ppt_update_entries(): Found large PDE, data 0x%p\n", 
                    LowerPageTablePA));
                return;

            } 
            else 
            {
            	dprint(PRINT_ERROR,(
                    "ppt_update_entries(): Failed to find lower page table (pl%d) guest VA, data 0x%p, status 0x%08X\n",
                    PageTableLevel - 1, 
                    LowerPageTablePA, 
                    Status));
                panic("");
            }
        }

        LowerPageTableGuestVA = LowerPageTable->gvaddr;
    }

    ppt_update_entries (
        (PVOID)LowerPageTableGuestVA, 
        PageTableLevel - 1, 
        gvaddr, 
        gpaddr, 
        bLargePage);
}

static VOID NTAPI ppt_create_mapping (
  gpaddr_t PhysicalAddress,
  gvaddr_t VirtualAddress,
  BOOLEAN bLargePage
)
{
  	struct page_info *pPdePage;
  	NTSTATUS Status;
	gpaddr_t gpaddr;
	gvaddr_t gvaddr;
	
  	Status = MmFindPageByGPA (ppt_pd_gpaddr, &pPdePage);
  	assert((NT_SUCCESS (Status)), 
		("ppt_create_mapping():ppt_pd_gpaddr not initialized"));

  	gpaddr = PhysicalAddress & ALIGN_4KPAGE_MASK;
  	gvaddr =  (VirtualAddress & ALIGN_4KPAGE_MASK);

    ppt_update_entries(
      	(PVOID)pPdePage->gvaddr, 
      	2, 
      	gvaddr, 
      	gpaddr, 
      	bLargePage);
}

static NTSTATUS NTAPI ppt_walk_guest_pt (
  PULONG PageTable,
  UCHAR bLevel
)
{
    ULONG i;
    gvaddr_t VirtualAddress;
    gpaddr_t PhysicalAddress;
    PULONG LowerPageTable;

    if (!MmIsAddressValid (PageTable))
        return STATUS_SUCCESS;

    if (bLevel != 1)
        return STATUS_UNSUCCESSFUL;

    // must be level 1
    // 10 bits
    for (i = 0; i < 0x400; i++)
    {
        if (PageTable[i] & P_PRESENT) 
        {
            // get VirtualAddress to map
            VirtualAddress = (((LONG)(&PageTable[i]) - WIN_PTE_BASE) << 10);

            PhysicalAddress = PageTable[i] & ALIGN_4KPAGE_MASK;

            if ( VirtualAddress >= WIN_PTE_BASE 
                &&  VirtualAddress <= WIN_PTE_TOP_X86)
            {
                // guest pagetable stuff here - so don't map it
                continue;
            }

            // blevel == 1, just map it in host pagetable
            ppt_create_mapping (PhysicalAddress, VirtualAddress, FALSE);
        }
    }

    return STATUS_SUCCESS;
}


// Create private pagetable corresponding to the current kernel mapping.
NTSTATUS NTAPI ppt_create(void)
{
	PULONG pPde = (PULONG) WIN_PDE_BASE;
	PULONG pPte;
	ULONG32 pde_index;
	gpaddr_t avail_gpaddr;
	gvaddr_t avail_gvaddr;
	gvaddr_t split_page_gva;
	//gvaddr_t ppt_pt_gvaddr;
	//gpaddr_t ppt_pt_gpaddr;
	
    // just walk kernel space, va >= 0x80000000
    for (pde_index = 0x200; pde_index < 0x400; pde_index++)
    {
        if (!(pPde[pde_index] & P_PRESENT)) 
        {
            continue;
        }

        if (pPde[pde_index] & P_LARGE)
        {
            // 4M page
            avail_gvaddr = (pde_index << 22);
            avail_gpaddr = pPde[pde_index] & ALIGN_4KPAGE_MASK;

            if ( avail_gvaddr >= WIN_PTE_BASE 
                && avail_gvaddr <= WIN_PTE_TOP_X86)
            {
                // guest pagetable stuff here - so don't map it
                continue;
            }

            // make 4M page into 4k pages in host
            for (split_page_gva =  avail_gvaddr + 0x0 * PAGE_SIZE;
                split_page_gva <  avail_gvaddr + 0x400 * PAGE_SIZE;
                split_page_gva += PAGE_SIZE, avail_gpaddr += PAGE_SIZE)
            {
                ppt_create_mapping (avail_gpaddr, split_page_gva, FALSE);
            }
        }
        else
        {
            // 4k page
            pPte = (PULONG)((PUCHAR) WIN_PTE_BASE + (pde_index << 10) * 4);
            ppt_walk_guest_pt(pPte, 1);
        }
    }
	
	/*for (pde_index = 0x200; pde_index < 0x400; pde_index++)
	{
		ppt_pt_gvaddr = MmAllocatePages(1, &ppt_pt_gpaddr);
		assert((ppt_pt_gvaddr), "ppt_init():allocation error");
		
		memcpy((PVOID)ppt_pt_gvaddr, (PVOID)(WINXP_PTE_BASE + pde_index * PT_PAGETABLE_ENTRIES * BYTES_OF_ENTRIES), 
			PAGE_SIZE);
		((PULONG)ppt_pd_gvaddr)[pde_index] = (pPde[pde_index] & 0x00000fff) | (gpaddr_to_gfn(ppt_pt_gpaddr));
	}*/
	
    return STATUS_SUCCESS;
}

VOID NTAPI ppt_init (struct arch_phy* parch)
{
	ppt_pd_gvaddr = MmAllocateContiguousPages(WIN_PDE_PAGES, &ppt_pd_gpaddr, TRUE);
	assert((ppt_pd_gvaddr), ("ppt_init():allocation error"));

	arch = parch;
	arch->ppt.private_table = gpaddr_to_gfn(ppt_pd_gpaddr);

	print("Private Page Table (PPT) is enabled\n");
}

VOID NTAPI ppt_monitor_guest_pagetable(void)
{
	gpaddr_t pd_gpaddr, pt_gpaddr;
	gvaddr_t pPde = WIN_PDE_BASE;
	gvaddr_t pPte;
	gfn_t pd_gfn, pt_gfn;
	ULONG32 pde_index;
	
	// disable writing access on PD
	#ifdef _X86_
	pd_gpaddr = MmGetPhysicalAddress((PVOID)pPde).LowPart;
	#elif defined (_X64_)
	pd_gpaddr = MmGetPhysicalAddress((PVOID)pPde).QuadPart;
	#endif
	assert((pd_gpaddr), ("ppt_monitor_guest_pagetable(): Detect WINXP_PDE_BASE failed"));

	pd_gfn = gpaddr_to_gfn(pd_gpaddr);
	arch->p2m.p2m_create_mapping(pd_gfn, pd_gfn, P2M_READABLE | P2M_EXECUTABLE, FALSE);

	// disable writing access on all kernel space PTE.
	for (pde_index = 0x200; pde_index < 0x400; pde_index++)
	{
		if ( (!(((PULONG)pPde)[pde_index] & P_PRESENT)) || 
			(((PULONG)pPde)[pde_index] & P_LARGE))
        {
        	// [TODO] Large page PDE need other operations on it. Implement this in the future.
            continue;
        }
		
		pPte = WIN_PTE_BASE + pde_index * PT_PAGETABLE_ENTRIES * BYTES_OF_ENTRIES; 
		assert((MmIsAddressValid((PVOID)pPte)), ("ppt_monitor_guest_pagetable():Invalid pPte"));
		assert(( ((pde_index << 22) < WIN_PTE_BASE) && 
				 ((pde_index << 22) > WIN_PTE_BASE)),
			("ppt_monitor_guest_pagetable(): include page table area?"));

		#ifdef _X86_
		pt_gpaddr = MmGetPhysicalAddress((PVOID)pPte).LowPart;
		#elif defined (_X64_)
		pt_gpaddr = MmGetPhysicalAddress((PVOID)pPte).QuadPart;
		#endif
		
		pt_gfn = gpaddr_to_gfn(pt_gpaddr);
		arch->p2m.p2m_create_mapping(pt_gfn, pt_gfn, P2M_READABLE | P2M_EXECUTABLE, FALSE);
	}
	
}

#endif
