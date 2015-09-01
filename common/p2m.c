/****************************
* 2011.1     Miao Yu     	Implement Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#include <vis/p2m.h>
#include <vis/hvm.h>
#include <vis/arch.h>
#include <arch/vmx/ept.h>

VOID NTAPI p2m_init(struct arch_phy* arch )
{
	if(paging_mode_ept(arch))
	{
		//Obviously, the current architecture supports EPT
		ept_init(arch);
	}
}