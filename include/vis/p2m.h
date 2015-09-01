/****************************
* 2011.1     Miao Yu     	Implement Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/spinlock.h>
#include <vis/mm.h>

#define P2M_READABLE			0x01
#define P2M_WRITABLE			0x02
#define P2M_EXECUTABLE			0x04
#define P2M_FULL_ACCESS			(P2M_READABLE | P2M_WRITABLE | P2M_EXECUTABLE)

typedef enum
{
  	P2M_UPDATE_MFN = 1,
	P2M_UPDATE_REMAININGS = 2,
	P2M_UPDATE_MT = 4,
	P2M_UPDATE_ALL = 7
} P2M_UPDATE_TYPE;

struct p2m_arch
{
    spinlock_t lock;
    ULONG holder;  /* processor which holds the lock */
    BOOLEAN need_flush;
	//BOOLEAN can_remap; //[TODO] Ugly design, Currently I enable it when all the cores have Vis installed. 
	
	/* Shadow translated domain: P2M mapping */
    pagetable_t p2m_table;
	
	gpaddr_t spare_page_gpaddr;
	gvaddr_t spare_page_gvaddr;

    NTSTATUS (NTAPI *p2m_create_mapping)(gfn_t gfn, mfn_t mfn, ULONG32 p2m_type, 
		BOOLEAN bLargePage);
	VOID (NTAPI *p2m_tlb_flush)(void);
	VOID (NTAPI *p2m_vpid_flush)(void);
	NTSTATUS (NTAPI *p2m_create_identity_map)(void);

	NTSTATUS (NTAPI *p2m_update_mapping)(gfn_t gfn, mfn_t mfn, ULONG32 p2m_type, 
		BOOLEAN bLargePage, P2M_UPDATE_TYPE op_type);

	NTSTATUS (NTAPI *p2m_update_all_mapping)(ULONG32 p2m_type);
};

VOID NTAPI p2m_init(struct arch_phy* arch);