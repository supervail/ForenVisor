/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#pragma once
#include <vis/p2m.h>
#include <vis/hvm.h>
#include <vis/mm.h>
#include <vis/config.h>

#ifdef CONFIG_USE_PRIVATE_PAGETABLE
#include <vis/ppt.h>
#endif

struct arch_phy
{

	#ifdef CONFIG_USE_PRIVATE_PAGETABLE
	struct ppt_arch ppt;
	#endif

	struct mm_arch mm;
	struct p2m_arch p2m;
    struct hvm_arch hvm;
};

VOID NTAPI arch_init(struct arch_phy* arch);
