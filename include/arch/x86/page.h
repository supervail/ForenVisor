/****************************
* 2011.1     Miao Yu     	Implement Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

/*
 * The following code is extracted from Xen 4.
 */
#pragma once

/* This is used by address translations on x86 platform */
#define P_PRESENT			0x01
#define P_WRITABLE			0x02
#define P_USERMODE			0x04
#define P_WRITETHROUGH		0x08
#define P_CACHE_DISABLED	0x10
#define P_ACCESSED			0x20
#define P_DIRTY				0x40
#define P_LARGE				0x80
#define P_GLOBAL			0x100

#define PT_PAGETABLE_SHIFT      12
#define PD_PAGETABLE_SHIFT      22			

#define PAGETABLE_ORDER         10
#define OFFSET_MASK				((1<<PAGETABLE_ORDER) - 1)
#define PD_MASK					(OFFSET_MASK << PD_PAGETABLE_SHIFT)

#define PD_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define PT_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)

#define PT_LEVEL_OFFSET(gvaddr) (((gvaddr_t)gvaddr >> PT_PAGETABLE_SHIFT) & OFFSET_MASK)
#define PD_LEVEL_OFFSET(gvaddr) (((gvaddr_t)gvaddr >> PD_PAGETABLE_SHIFT) & OFFSET_MASK)

#define BYTES_OF_ENTRIES		(sizeof(ULONG))

/* Convert between frame number and address formats.  */
#define gfn_to_gpaddr(gfn)	((gpaddr_t)(gfn) << PAGE_SHIFT)
#define gpaddr_to_gfn(addr)	((gfn_t)((addr & 0xfffff000) >> PAGE_SHIFT))

#define gvfn_to_gvaddr(gvfn)	((gvaddr_t)(gvfn) << PAGE_SHIFT)
#define gvaddr_to_gvfn(addr)	((gvfn_t)((addr & 0xfffff000) >> PAGE_SHIFT))

#define mfn_to_mpaddr(mfn)	((mpaddr_t)(mfn) << PAGE_SHIFT)
#define mpaddr_to_mfn(addr)	((mfn_t)((addr & 0xfffff000) >> PAGE_SHIFT))

