/****************************
* 2011.1     Miao Yu     	Implement Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

/*
* The following code is extracted from Xen 4.
*/
#pragma once

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#define ROOT_PAGETABLE_SHIFT    L4_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L4_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L4_PAGETABLE_ENTRIES

/* Convert between frame number and address formats.  */
#define gfn_to_gpaddr(gfn)	((gpaddr_t)(gfn) << PAGE_SHIFT)
#define gpaddr_to_gfn(addr)	((gfn_t)((addr & 0x000ffffffffff000) >> PAGE_SHIFT))

#define gvfn_to_gvaddr(gvfn)	((gvaddr_t)(gvfn) << PAGE_SHIFT)
#define gvaddr_to_gvfn(addr)	((gvfn_t)((addr & 0xfffffffffffff000) >> PAGE_SHIFT))

#define mfn_to_mpaddr(mfn)	((mpaddr_t)(mfn) << PAGE_SHIFT)
#define mpaddr_to_mfn(addr)	((mfn_t)((addr & 0xfffffffffffff000) >> PAGE_SHIFT))

