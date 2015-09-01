/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
                                   Add facade functions to hide Vis hypervisor.  
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/types.h>
#include <vis/traps.h>
// I copy most of the definitions from Xen 4.

#if defined(_X86_)
        #include <arch/x86/page.h>
#elif defined(_X64_)
        #include <arch/x64/page.h>
#endif

#define ITL_TAG	'LTI'

#define P_PRESENT			0x01
#define P_WRITABLE			0x02
#define P_USERMODE			0x04
#define P_WRITETHROUGH		0x08
#define P_CACHE_DISABLED	0x10
#define P_ACCESSED			0x20
#define P_DIRTY				0x40
#define P_LARGE				0x80
#define P_GLOBAL			0x100

#define ALIGN_4KPAGE_MASK   0xfffff000


typedef gfn_t pagetable_t;
#define pagetable_get_fn(x)    ((gfn_t)(x))

#define PG_shift(idx)       (BITS_PER_LONG - (idx))
#define PG_mask(x, idx)     (x ## UL << PG_shift(idx))

/* Page Allocation Type: How to use/free these pages in the future? */
#define PGT_PAT_dont_free       PG_mask(1, 6) 
#define PGT_PAT_pool            PG_mask(2, 6)
#define PGT_PAT_contiguous      PG_mask(3, 6) 
#define PGT_PAT_mask     		PG_mask(3, 6) 

struct mm_arch
{
    gfn_t   mm_lowest_gfn;
    gfn_t   mm_highest_gfn;
    ULONG   mm_num_gfn; 
};

struct page_info
{
    LIST_ENTRY le;

    /* Reference count  */
    ULONG32 count_ref;

    /* and various PGT_xxx flags and fields */
    // Must use ULONG type, since it takes 32bit in X86 and 64bit in X64
    // PGT_xxx macros has compatibility with different platforms.
    ULONG type_info; 

    //for PGT_PAT_contiguous only
    ULONG32 uNumberOfPages;   
	
	gvaddr_t gvaddr;
	gfn_t gfn;
    mfn_t mfn;

	// for concealing page usage, avoid seal the same page on multi-core platform 
	BOOLEAN remapped;

};

NTSTATUS NTAPI MmFindPageByGPA (
  gpaddr_t gpaddr,
  struct page_info **ppg_info
);

NTSTATUS NTAPI MmFindPageByGVA (
  gvaddr_t gvaddr,
  struct page_info **ppg_info
);

/**
 * effects: Allocate <uNumberOfPages> pages from memory.
 */
gvaddr_t NTAPI MmAllocatePages (
  ULONG uNumberOfPages,
  gpaddr_t *pFirstPagePA,
  BOOLEAN hide_this_page
);

/**
 * effects: Allocate Contiguous Pages from memory.
 */
gvaddr_t NTAPI MmAllocateContiguousPages (
  ULONG uNumberOfPages,
  gpaddr_t *pFirstPagePA,
  BOOLEAN hide_this_page
);

/**
 * effects: Allocate Contiguous Pages from memory with the indicated cache strategy.
 */
gvaddr_t NTAPI MmAllocateContiguousPagesSpecifyCache (
  ULONG uNumberOfPages,
  gpaddr_t *pFirstPagePA,
  ULONG CacheType,
  BOOLEAN hide_this_page
);

/*
  * Allocate a page for spare page. Its gva will be used again when finalizing the MM module.
  * Its gpa will be used in remapping procedure in p2m module to achieve transparency.
  */
extern VOID NTAPI mm_init (struct arch_phy* parch, PDRIVER_OBJECT pDriverObject);

extern VOID NTAPI mm_finalize (void);

NTSTATUS NTAPI mm_hide_vis_pages (struct arch_phy* arch);
//extern NTSTATUS NTAPI mm_hide_vis_data(struct arch_phy* arch);
extern VOID NTAPI mm_hide_vis_code (void);
//extern VOID NTAPI mm_reveal_vis_code (void);
extern NTSTATUS NTAPI mm_reveal_all_pages(void);
extern NTSTATUS NTAPI mm_map_machine_pfns (struct arch_phy* arch);

// Effect:Hide Vis code segment via requiring modifying the P2M page table.
/*#define mm_trig_hiding_viscode(DriverObject) __asm \
	{ \
		__asm mov eax, CPUID_EPT_HIDE_VISCODE \
		__asm mov ecx, DriverObject \
		__asm call   getip \
		__asm getip:  pop edx \
		__asm cpuid \
	}
*/

