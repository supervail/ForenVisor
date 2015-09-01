/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#include <vis/arch.h>
#include <vis/spinlock.h>

VOID NTAPI arch_init(struct arch_phy* arch)
{
	arch->p2m.holder = NO_HOLDER;
}