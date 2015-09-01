/****************************
* 2011.1     Miao Yu     Implement case study for Vis hypervisor. 
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/config.h>

#ifdef EXAMPLE_MEM_DUMP

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos)   \
	 (((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
	 (((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli)  \
	 (((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds)	 \
	 (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define MINUTES(minutes)	 \
	 (((signed __int64)(minutes)) * SECONDS(60L))

#define HOURS(hours)		 \
	 (((signed __int64)(hours)) * MINUTES(60L))
	 

//extern VOID NTAPI dump_phys_mem(struct arch_phy* arch);

extern VOID NTAPI dump_io_write(gvfn_t gvfn, VOID* content, ULONG content_size);
extern VOID NTAPI dump_finish(void);
//extern VOID NTAPI dump_on_guest_write(struct arch_phy* arch, gpaddr_t gpxaddr);
extern VOID NTAPI dump_remainings(struct arch_phy* arch, PBOOLEAN done);

extern VOID NTAPI dump_init(void);
extern VOID NTAPI dump_finalize(void);

extern BOOLEAN NTAPI ept_handle_violation_ext (struct arch_phy* arch, PHYSICAL_ADDRESS gpa);
extern VOID NTAPI VmxDispatchCrAccess_ext (struct arch_phy* arch);
extern BOOLEAN NTAPI VmxDispatchCpuid_ext (PGUEST_REGS GuestRegs, struct arch_phy* arch, ULONG fn);


#endif
