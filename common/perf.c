/****************************
* 2011.1     Miao Yu     	Implement Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#include <vis/perf.h>
#include <vis/config.h>

#ifdef CONFIG_PERF_ENABLE
#include <vis/spinlock.h>

//spinlock_t perf_lock;
struct arch_phy* arch;

ULONG64 perf_read_tsc(void)
{
	__asm{rdtsc}
}

ULONG64 NTAPI perf_start_timer(void)
{
	ULONG64 tsc;
	
	tsc = perf_read_tsc();
	return tsc;
}

ULONG64 NTAPI perf_get_execution_time(ULONG64 start_timer_record)
{
	ULONG64 end_timer;

	if(!start_timer_record)
		return 0;
	
	end_timer= perf_read_tsc();
	return (end_timer - start_timer_record);
}

VOID NTAPI perf_init(struct arch_phy* parch)
{
	//spin_lock_init(&perf_lock);
	arch = parch;
}

VOID NTAPI perf_handle_request(ULONG32 fn, PCPU cpu, ULONG64 val_from_guest, PULONG64 val_to_guest)
{
	switch(fn)
	{
		case PERF_VMEXIT_TSC:
			// Calculate in guest, just return the needed TSC to guest
			{
				*val_to_guest = cpu->last_hypervisor_start_tsc;
			}
				
			break;
		case PERF_VMRESUME_TSC:
			{
				cpu->ctl_measure_vmresume = 1;
			}
				
			break;
		case PERF_FLUSH_EPT:
			{
				arch->p2m.p2m_update_mapping(0, 0, P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MFN);
			}
		
			break;
		default:
			panic("Invalid Perf Request");
	}
}
#endif
