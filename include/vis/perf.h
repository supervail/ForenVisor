/****************************
* 2011.1     Miao Yu     	Implement Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/config.h>
#include <vis/vcpu.h>
#include <vis/arch.h>

#ifdef CONFIG_PERF_ENABLE

#define PERF_CPUID_BASE 	0x10000000
#define PERF_VMEXIT_TSC		0x10000000
#define PERF_VMRESUME_TSC	0x10000001
#define PERF_FLUSH_EPT		0x10000002

#define PERF_CPUID_LIMIT	0x10000010

#define rdtsc() perf_read_tsc()

extern ULONG64 perf_read_tsc(void);
extern ULONG64 NTAPI perf_start_timer(void);
extern ULONG64 NTAPI perf_get_execution_time(ULONG64 start_timer_record);
extern VOID NTAPI perf_init(struct arch_phy* parch);
extern VOID NTAPI perf_handle_request(ULONG32 fn, PCPU cpu, ULONG64 val_from_guest, PULONG64 val_to_guest);

#endif

