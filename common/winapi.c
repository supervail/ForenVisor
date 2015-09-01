/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file for supporting multi-OS in the future.
* 
*****************************/

#include <vis/winapi.h>

VOID win_memcpy(PVOID dest, PVOID src)
{
	int i = 0;
	PULONG32 pdest = (PULONG32)dest;
	PULONG32 psrc = (PULONG32)src;
		
	for(i = 0; i < PAGE_SIZE / 4; i++)
		pdest[i] = psrc[i];
}

