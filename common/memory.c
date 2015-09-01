/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
                                   Add facade functions to hide Vis hypervisor.  
* 
*****************************/

#include <vis/mm.h>
#include <vis/config.h>
#include <vis/types.h>
#include <vis/arch.h>
#include "winapi.h"
#include <libs/winapi.h>

static LIST_ENTRY list_alloc_pages;
static KSPIN_LOCK list_alloc_pages_lock;
static ULONG lock_holder = NO_HOLDER;

static LIST_ENTRY* list_last_checkpoint = &list_alloc_pages;
static LIST_ENTRY* list_cur_checkpoint;

//static gpaddr_t spare_page_gpaddr = 0;
//static gvaddr_t spare_page_gvaddr = 0;

struct arch_phy* arch;
PDRIVER_OBJECT DriverObject;

//SystemBasicInfo
typedef struct BasicMachineInfo {
	ULONG AlwaysZero;
	ULONG KeMaximumIncrement;
	ULONG MmPageSize;
	ULONG MmNumberOfPhysicalPages;
	ULONG MmLowestPhysicalPage;
	ULONG MmHighestPhysicalPage;
	ULONG MmLowestUserAddress;
	ULONG MmLowestUserAddress1;
	ULONG MmHighestUserAddress;
	ULONG KeActiveProcessors;
	char KeNumberProcessors;
} BASICSYSTEMINFO, *PBASICSYSTEMINFO;

static struct page_info* NTAPI mm_save_page (
	gvaddr_t gvaddr,
    gpaddr_t gpaddr,
    mpaddr_t mpaddr,
  	ULONG pg_type,
  	ULONG uNumberOfPages
)
{
	gfn_t gfn;
    mfn_t mfn;
  	struct page_info *new_pginfo;

	assert(gvaddr, ("mm_save_page(): gvaddr is a null pointer"));

  	new_pginfo = ExAllocatePoolWithTag (NonPagedPool, 
		sizeof (struct page_info), ITL_TAG);

	assert(new_pginfo, ("mm_save_page(): Insufficient Memory Resources"));
	
  	RtlZeroMemory (new_pginfo, sizeof (struct page_info));
  
	gfn = gpaddr_to_gfn(gpaddr);
	mfn = mpaddr_to_mfn(mpaddr);

	new_pginfo->count_ref = 0;
	new_pginfo->type_info = pg_type;
	new_pginfo->mfn = mfn;
	new_pginfo->gfn = gfn;
	new_pginfo->gvaddr = gvaddr;
	new_pginfo->uNumberOfPages = uNumberOfPages;

    DDKExInterlockedInsertTailList (&list_alloc_pages, &new_pginfo->le, 
		&list_alloc_pages_lock);

	list_cur_checkpoint = &new_pginfo->le;
	dprint(PRINT_INFO, ("gva: 0x%llx, gvfn: 0x%llx, gfn: 0x%llx, mfn: 0x%llx", 
		gvaddr, gvaddr_to_gvfn(gvaddr), gfn, mfn));

  return new_pginfo;
}

NTSTATUS NTAPI mm_map_machine_pfns (struct arch_phy* arch)
{
	/* [TODO] Currently I choose to map all the pfns on the x86 platform.
	  * A more precise solution is to query the os available pfns and mapping them
	  * However, this is OS version specied and seems not very good. 
	  */
	NTSTATUS status;
	gfn_t gfn;
	
	if(!arch->p2m.p2m_create_identity_map)
		return STATUS_UNSUCCESSFUL;

	arch->p2m.p2m_create_identity_map();
	
	return STATUS_SUCCESS;
}

VOID NTAPI mm_hide_vis_code (void)
{
	/* 
	  * We don't need to really *HIDE* the Vis code segment now. Instead, we register them in the <list_alloc_pages>
	  * The reason is that, all pages appeared as entries in the <list_alloc_pages> struct will be concealed.
	  */
	ULONG mapped_sizes;
	gpaddr_t gpaddr;
	gvaddr_t gvaddr;
	ULONG upages;

	upages = BYTES_TO_PAGES (DriverObject->DriverSize);
	
	for (mapped_sizes = 0; mapped_sizes < DriverObject->DriverSize - PAGE_SIZE; 
		mapped_sizes += PAGE_SIZE)
	{
		gvaddr = (gvaddr_t)DriverObject->DriverStart + mapped_sizes;

	#if defined (_X86_)
	    gpaddr = MmGetPhysicalAddress ((PVOID)gvaddr).LowPart;
	#elif defined (_X64_)
		gpaddr = MmGetPhysicalAddress ((PVOID)gvaddr).QuadPart;
	#endif
	
		mm_save_page(gvaddr, gpaddr, arch->p2m.spare_page_gpaddr, PGT_PAT_dont_free, upages);
	}
}

/*VOID NTAPI mm_reveal_vis_code (void)
{
	/* 
	  * We don't need to really *HIDE* the Vis code segment now. Instead, we register them in the <list_alloc_pages>
	  * The reason is that, all pages appeared as entries in the <list_alloc_pages> struct will be concealed.
	  */
	/*ULONG mapped_sizes;
	gpaddr_t gpaddr;
	gvaddr_t gvaddr;
	struct page_info* pginfo;
	ULONG upages = BYTES_TO_PAGES (DriverObject->DriverSize);
	
	for (mapped_sizes = 0; mapped_sizes < DriverObject->DriverSize; 
		mapped_sizes += PAGE_SIZE)
	{
		gvaddr = (gvaddr_t)DriverObject->DriverStart + mapped_sizes;

	#if defined (_X86_)
	    gpaddr = MmGetPhysicalAddress ((PVOID)gvaddr).LowPart;
	#elif defined (_X64_)
		gpaddr = MmGetPhysicalAddress ((PVOID)gvaddr).QuadPart;
	#endif
		MmFindPageByGPA(gpaddr, &pginfo);
		assert(pginfo, "mm_reveal_vis_code(): pginfo is a null pointer");
		pginfo->remapped = FALSE;
		
		arch->p2m.p2m_create_mapping(gpaddr_to_gfn(gpaddr), gpaddr_to_gfn(gpaddr), 
			(P2M_READABLE | P2M_WRITABLE | P2M_EXECUTABLE), FALSE);
	}
}*/


NTSTATUS NTAPI mm_hide_vis_pages (struct arch_phy* arch)
{
	struct page_info *pg_info, *start_pginfo;
	gfn_t gfn;
	KIRQL old_irql;
	
	if(!arch->p2m.p2m_update_mapping)
		return STATUS_UNSUCCESSFUL;

	start_pginfo = (struct page_info*)list_cur_checkpoint->Flink;
	pg_info = (struct page_info*)list_last_checkpoint->Flink;

	if(list_cur_checkpoint->Blink == list_last_checkpoint)
	{
		// No new mapping saved in P2m table
		return STATUS_SUCCESS;
	}

	if(lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock (&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}
	
	do
	{
		pg_info = CONTAINING_RECORD (pg_info, struct page_info, le);

		if(!pg_info->remapped)
		{
			arch->p2m.p2m_update_mapping(pg_info->gfn, pg_info->mfn, 
				P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MFN);
			pg_info->remapped = TRUE;
		}
		 pg_info = (struct page_info *) pg_info->le.Flink;
	} while(start_pginfo != pg_info);

	list_last_checkpoint = list_cur_checkpoint;
	if(lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock (&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmFindPageByGPA (
  gpaddr_t gpaddr,
  struct page_info **ppg_info
)
{
	struct page_info *pg_info, *last_pg_info;
	gfn_t gfn;
	KIRQL old_irql;

	assert(ppg_info, ("MmFindPageByGPA(): ppg_info is a null pointer"));

	if(lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock (&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}

	gfn = gpaddr_to_gfn(gpaddr);
	pg_info = (struct page_info*)list_alloc_pages.Flink;
	
	while (pg_info != (struct page_info*) &list_alloc_pages) {	
		pg_info = CONTAINING_RECORD (pg_info, struct page_info, le);

	    if (pg_info->gfn == gfn) {
	    	*ppg_info = pg_info;
			pg_info->count_ref++;
			
	      	if(lock_holder == KeGetCurrentProcessorNumber())
			{
				KeReleaseSpinLock (&list_alloc_pages_lock, old_irql);
				lock_holder = NO_HOLDER;
			}
	      	return STATUS_SUCCESS;
	    }
		// [Superymk] Debug here
		if(!pg_info->le.Flink) __asm {int 3}

		last_pg_info = pg_info;
	    pg_info = (struct page_info *) pg_info->le.Flink;
	}

	if(lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock (&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI MmFindPageByGVA (
  gvaddr_t gvaddr,
  struct page_info **ppg_info
)
{
  	struct page_info *pg_info;
	gvfn_t gvfn, pg_gvfn;
	KIRQL old_irql;

	assert(ppg_info, ("MmFindPageByGVA(): ppg_info is a null pointer"));

	if(lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock (&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}

	gvfn = gvaddr_to_gvfn(gvaddr);
	pg_info = (struct page_info*)list_alloc_pages.Flink;
	while (pg_info != (struct page_info*) &list_alloc_pages) {	
		pg_info = CONTAINING_RECORD (pg_info, struct page_info, le);

	    if (gvaddr_to_gvfn(pg_info->gvaddr) == gvfn) {
	    	*ppg_info = pg_info;
			pg_info->count_ref++;
			
	      	if(lock_holder == KeGetCurrentProcessorNumber())
			{
				KeReleaseSpinLock (&list_alloc_pages_lock, old_irql);
				lock_holder = NO_HOLDER;
			}
	      	return STATUS_SUCCESS;
	    }
	    pg_info = (struct page_info *) pg_info->le.Flink;
	}

	if(lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock (&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_UNSUCCESSFUL;
}

/**
 * effects: Allocate <uNumberOfPages> pages from memory.
 */
gvaddr_t NTAPI MmAllocatePages (
  ULONG uNumberOfPages,
  gpaddr_t *pFirstPagePA,
  BOOLEAN hide_this_page
)
{
	gvaddr_t PageVA, FirstPage;
  	gpaddr_t PagePA;
  	NTSTATUS Status;
	struct page_info* pginfo;
		
 	ULONG i;

  	if (!uNumberOfPages)
    	return NULL;

  	FirstPage = PageVA = (gvaddr_t)ExAllocatePoolWithTag (NonPagedPool, 
		uNumberOfPages * PAGE_SIZE, ITL_TAG);
  	assert(PageVA, ("MmAllocatePages(): Memory allocation error"));

  	RtlZeroMemory ((PVOID)PageVA, uNumberOfPages * PAGE_SIZE);

  	if (pFirstPagePA)
	#if defined (_X86_)
    	*pFirstPagePA = MmGetPhysicalAddress ((PVOID)PageVA).LowPart;
	#elif defined (_X64_)
		*pFirstPagePA = MmGetPhysicalAddress ((PVOID)PageVA).QuadPart;
	#endif

	if(hide_this_page)
	{
		for (i = 0; i < uNumberOfPages; i++) {
		    // map to the same addresses in the host pagetables as they are in guest's
		#if defined (_X86_)
		    PagePA = MmGetPhysicalAddress ((PVOID)PageVA).LowPart;
		#elif defined (_X64_)
			PagePA = MmGetPhysicalAddress ((PVOID)PageVA).QuadPart;
		#endif
		
		    pginfo = mm_save_page(PageVA, PagePA, arch->p2m.spare_page_gpaddr, 
		    	!i ? PGT_PAT_pool : PGT_PAT_dont_free, uNumberOfPages);

		    PageVA = PageVA + PAGE_SIZE;
		}
	}
	
  	return FirstPage;
}
/**
 * effects: Allocate Contiguous Pages from memory.
 */
gvaddr_t NTAPI MmAllocateContiguousPages (
  ULONG uNumberOfPages,
  gpaddr_t *pFirstPagePA,
  BOOLEAN hide_this_page
)
{
    return MmAllocateContiguousPagesSpecifyCache(
        uNumberOfPages,
        pFirstPagePA,
        MmCached,
        hide_this_page);
}
/**
 * effects: Allocate Contiguous Pages from memory with the indicated cache strategy.
 */
gvaddr_t NTAPI MmAllocateContiguousPagesSpecifyCache (
  ULONG uNumberOfPages,
  gpaddr_t *pFirstPagePA,
  ULONG CacheType,
  BOOLEAN hide_this_page
)
{
	gvaddr_t PageVA, FirstPage;
  	gpaddr_t PagePA;
  	PHYSICAL_ADDRESS l1, l2, l3;
  	NTSTATUS Status;
	struct page_info* pginfo;
  	ULONG i;

  	if (!uNumberOfPages)
    	return NULL;

	l1.QuadPart = 0;
	l2.QuadPart = -1;
	l3.QuadPart = 0x200000;    // 0x10000 ?

  	FirstPage = PageVA = (gvaddr_t)MmAllocateContiguousMemorySpecifyCache (
      	uNumberOfPages * PAGE_SIZE, 
      	l1, 
     	l2, 
      	l3, 
      	CacheType);
  	if (!PageVA)
    	return NULL;

  	RtlZeroMemory ((PVOID)PageVA, uNumberOfPages * PAGE_SIZE);

#if defined (_X86_)
  	PagePA = MmGetPhysicalAddress ((PVOID)PageVA).LowPart;
#elif defined (_X64_)
	PagePA = MmGetPhysicalAddress ((PVOID)PageVA).QuadPart;
#endif

  	if (pFirstPagePA)
    	*pFirstPagePA = PagePA;

	if(hide_this_page)
	{
		for (i = 0; i < uNumberOfPages; i++) {
	    	// map to the same addresses in the host pagetables as they are in guest's
	    	pginfo = mm_save_page(PageVA, PagePA, arch->p2m.spare_page_gpaddr, 
	    		!i ? PGT_PAT_contiguous: PGT_PAT_dont_free, uNumberOfPages);

	    	PageVA = PageVA + PAGE_SIZE;
	    	PagePA += PAGE_SIZE;
	  	}
	}
	
  	return FirstPage;
}

static VOID NTAPI mm_init_globals(void)
{
	
	BASICSYSTEMINFO BasicSystemInfo;
	NTSTATUS rc;
	
	memset(&BasicSystemInfo, 0, sizeof(BASICSYSTEMINFO));
	rc=ZwQuerySystemInformation(SystemBasicInformation,
								&BasicSystemInfo,
								sizeof(BasicSystemInfo),
								NULL);

	assert((rc == STATUS_SUCCESS), ("mm_init_globals():Error in querying physical memory info."));

	arch->mm.mm_highest_gfn = (BasicSystemInfo.MmHighestPhysicalPage);
	arch->mm.mm_lowest_gfn = (BasicSystemInfo.MmLowestPhysicalPage);
	arch->mm.mm_num_gfn = BasicSystemInfo.MmNumberOfPhysicalPages;
}

static VOID NTAPI mm_init_spare_page(void)
{
	// [TODO] We need to add a spinlock to this function in order to make it thread-safe.
	PHYSICAL_ADDRESS l1, l2, l3;
	gpaddr_t *spare_page_gpaddr = &arch->p2m.spare_page_gpaddr;
	gvaddr_t *spare_page_gvaddr = &arch->p2m.spare_page_gvaddr;
	
	InitializeListHead (&list_alloc_pages);
  	KeInitializeSpinLock (&list_alloc_pages_lock);
  
	l1.QuadPart = 0;
  	l2.QuadPart = -1;
  	l3.QuadPart = 0x200000;
	*spare_page_gvaddr = (gvaddr_t)MmAllocateContiguousMemorySpecifyCache (
      PAGE_SIZE, 
      l1, 
      l2, 
      l3, 
      MmCached);
	assert(*spare_page_gvaddr, ("mm_init_spare_page(): spare_page_gvaddr is a null pointer"));
	RtlZeroMemory ((PVOID)*spare_page_gvaddr, PAGE_SIZE);

	#if defined (_X86_)
  		*spare_page_gpaddr = MmGetPhysicalAddress ((PVOID)*spare_page_gvaddr).LowPart;
	#elif defined (_X64_)
		*spare_page_gpaddr = MmGetPhysicalAddress ((PVOID)*spare_page_gvaddr).QuadPart;
	#endif

	assert(spare_page_gpaddr, ("mm_init_spare_page(): spare_page_gpaddr has an invalid value"));
	}

/*
  * Allocate a page for spare page. Its gva will be used again when finalizing the MM module.
  * Its gpa will be used in remapping procedure in p2m module to achieve transparency.
  */
VOID NTAPI mm_init (struct arch_phy* parch, PDRIVER_OBJECT pDriverObject)
{
	arch = parch;
	DriverObject = pDriverObject;
	
	mm_init_globals();
	mm_init_spare_page();
}

VOID NTAPI mm_finalize (
)
{
	struct page_info *pg_info;
  	ULONG i;
  	PULONG64 Entry;

  	while (pg_info = 
	  	(struct page_info *) DDKExInterlockedRemoveHeadList (
	  		&list_alloc_pages, 
	  		&list_alloc_pages_lock)) 
  	{

    	pg_info = CONTAINING_RECORD (pg_info, struct page_info, le);			

    	switch (pg_info->type_info & PGT_PAT_mask) {
    		case PGT_PAT_pool:
      			ExFreePool ((PVOID)pg_info->gvaddr);
      			break;
    		case PGT_PAT_contiguous:
      			MmFreeContiguousMemorySpecifyCache ((PVOID)pg_info->gvaddr,
                           pg_info->uNumberOfPages * PAGE_SIZE, MmCached);
      			break;
    		case PGT_PAT_dont_free:
      			// this is not the first page in the allocation
      			break;
    		}
    	ExFreePool ((PVOID)pg_info);
 	}

	//Free SparePage
	MmFreeContiguousMemorySpecifyCache((PVOID)arch->p2m.spare_page_gvaddr, PAGE_SIZE, 
		MmCached);
	
	arch->p2m.spare_page_gpaddr = 0;
	arch->p2m.spare_page_gvaddr = 0;
	arch = 0;
}

/*NTSTATUS NTAPI mm_hide_vis_data(struct arch_phy* arch)
{
	NTSTATUS status;
	status = mm_map_machine_pfns(arch);
	if(!NT_SUCCESS (status))
		return status;

	/*status = mm_hide_vis_pages(arch);
	if(!NT_SUCCESS (status))
		return status; */ 

	/*return STATUS_SUCCESS;
}*/

NTSTATUS NTAPI mm_reveal_all_pages(void)
{
	struct page_info *pg_info;
	KIRQL old_irql;

	if(!arch->p2m.p2m_update_mapping)
		return STATUS_UNSUCCESSFUL;
		
	if(lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock (&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}

	pg_info = (struct page_info*)list_alloc_pages.Flink;
	while (pg_info != (struct page_info*) &list_alloc_pages) {	
		pg_info = CONTAINING_RECORD (pg_info, struct page_info, le);
		assert((pg_info),("mm_reveal_all_pages(): invalid pg_info"));

		pg_info->remapped = FALSE;
		
		arch->p2m.p2m_update_mapping(pg_info->gfn, pg_info->gfn, 
			P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MFN);
	    pg_info = (struct page_info *) pg_info->le.Flink;
	}

	if(lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock (&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_SUCCESS;
}
