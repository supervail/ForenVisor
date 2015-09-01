/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/config.h>
#include <vis/mm.h>

#ifdef CONFIG_USE_PRIVATE_PAGETABLE

#if !defined(_X86_)  
	#error [Error] Private Page Table works on i386 only.
#endif
	

#if ((OSVERSION_MASK & NTDDI_VERSION) == NTDDI_WINXP) //Windows XP
#define WIN_PTE_BASE        0xC0000000
#define WIN_PDE_BASE        0xC0300000
#define WIN_PTE_TOP_X86     0xC03FFFFF
#define WIN_PDE_TOP_X86     0xC0300FFF
#define WIN_PDE_PAGES       (BYTES_TO_PAGES(WIN_PDE_TOP_X86 - WIN_PDE_BASE))
#define WIN_PTE_PAGES		(BYTES_TO_PAGES(WIN_PTE_TOP_X86 - WIN_PTE_BASE))
#elif ((OSVERSION_MASK & NTDDI_VERSION) == NTDDI_WIN7) //Windows 7
#define WIN_PTE_BASE        0xC0000000
#define WIN_PDE_BASE        0xC0300000
#define WIN_PTE_TOP_X86     0xC03FFFFF
#define WIN_PDE_TOP_X86     0xC0300FFF
#define WIN_PDE_PAGES       (BYTES_TO_PAGES(WIN_PDE_TOP_X86 - WIN_PDE_BASE))
#define WIN_PTE_PAGES		(BYTES_TO_PAGES(WIN_PTE_TOP_X86 - WIN_PTE_BASE))
#endif



//for yupiwang's work
/*#define     GET_PDE_VADDRESS(va) ((((ULONG)(va) >> 22) << 2) + WINXP_PDE_BASE)
#define     GET_PTE_VADDRESS(va) ((((ULONG)(va) >> 12) << 2) + WINXP_PTE_BASE)

#define     GET_PDE_VOFFSET(va, base)   ((((ULONG)(va) >> 22) << 2) + base)
#define     GET_PTE_VOFFSET(va, base)   (((((ULONG)(va) >> 12) & 0x3ff) << 2) + base)


#define     GET_4KPAGE_PA(pte, va)      ((pte & 0xfffff000) + (va & 0xfff))
#define     GET_4MPAGE_PA(pde, va)      ((pde & 0xffc00000) + (va & 0x3fffff))

#define     IS_BIT_SET(value, bitno)    (BOOLEAN)(((ULONG64)value & (ULONG64)(1 << bitno)) != 0)

#define     IS_PAGE_PRESENT(x)  IS_BIT_SET(x, 0)
#define     IS_LARGE_PAGE(x)    IS_BIT_SET(x, 7)*/

struct ppt_arch
{
    spinlock_t lock;
    ULONG holder;  /* processor which holds the lock */
    BOOLEAN need_flush;
	//BOOLEAN can_remap; //[TODO] Ugly design, Currently I enable it when all the cores have Vis installed. 
	
	/* VMM Private page table */
    pagetable_t private_table;
	
	gpaddr_t spare_page_gpaddr;
	gvaddr_t spare_page_gvaddr;

    NTSTATUS (NTAPI *ppt_create_mapping)(gfn_t gfn, mfn_t mfn, ULONG32 p2m_type, 
		BOOLEAN bLargePage);
	VOID (NTAPI *p2m_tlb_flush)(void);
	VOID (NTAPI *p2m_vpid_flush)(void);
	NTSTATUS (NTAPI *p2m_create_identity_map)(void);

	NTSTATUS (NTAPI *p2m_update_mapping)(gfn_t gfn, mfn_t mfn, ULONG32 p2m_type, 
		BOOLEAN bLargePage, P2M_UPDATE_TYPE op_type);

	NTSTATUS (NTAPI *p2m_update_all_mapping)(ULONG32 p2m_type);
};

NTSTATUS NTAPI ppt_create (void);
extern VOID NTAPI ppt_init (struct arch_phy* parch);
VOID NTAPI ppt_monitor_guest_pagetable(void);
#endif

