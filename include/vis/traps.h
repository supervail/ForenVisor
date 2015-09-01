/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once

#include <ntddk.h>
#include <vis/config.h>
#include <vis/vcpu.h>

#define BP_KNOCK_EAX	100
#define BP_KNOCK_EAX_ANSWER 0x48656c6c	//Hell
#define BP_KNOCK_EBX_ANSWER 0x6f20576f  //o Wo
#define BP_KNOCK_EDX_ANSWER 0x726c6421	//rld!

#ifdef CONFIG_P2M_HIDE_CODE_DATA
#define CPUID_EPT_HIDE_VISCODE		0x1000
#define CPUID_EPT_REVEAL_VISCODE	0x1001
#endif 

#ifdef EXAMPLE_MEM_DUMP
#define START_MEM_DUMP				0x3000
#define QUERY_MEM_DUMP				0x4000
#endif

#ifdef CONFIG_PERF_ENABLE
#define CR3_WRITE_HANDLING	1
#define CR3_READ_HANDLING	2
#endif


//#define TEST_END					0x4000
typedef struct _NBP_TRAP *PNBP_TRAP;

// returns FALSE if the adjustment of guest RIP is not needed
typedef BOOLEAN (
  NTAPI * NBP_TRAP_CALLBACK
) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

typedef enum
{
  TRAP_DISABLED = 0,
  TRAP_GENERAL = 1,
  TRAP_MSR = 2,
  TRAP_IO = 3
} TRAP_TYPE;

// The following three structs will be used as trap's data structure.
/*typedef struct _NBP_TRAP_DATA_GENERAL
{
  ULONG TrappedVmExit;
  ULONG RipDelta;             // this value will be added to rip to skip the trapped instruction
} NBP_TRAP_DATA_GENERAL,
 *PNBP_TRAP_DATA_GENERAL;

typedef struct _NBP_TRAP_DATA_MSR
{
  ULONG32 TrappedMsr;
  UCHAR TrappedMsrAccess;
  UCHAR GuestTrappedMsrAccess;
} NBP_TRAP_DATA_MSR,
 *PNBP_TRAP_DATA_MSR;

typedef struct _NBP_TRAP_DATA_IO
{
  ULONG TrappedPort;
} NBP_TRAP_DATA_IO,
 *PNBP_TRAP_DATA_IO;*/


typedef struct _NBP_TRAP
{
  	LIST_ENTRY le;

  	TRAP_TYPE TrapType;
  	TRAP_TYPE SavedTrapType;

	ULONG TrappedVmExit;
  	ULONG RipDelta; 
  	NBP_TRAP_CALLBACK TrapCallback;

  	#ifdef CONFIG_PERF_ENABLE
  	ULONG64 last_execution_start_tsc;
	ULONG64 last_execution_time;
	ULONG64 last_dispatch_time;
	ULONG64 dispatch_resume_start_tsc;
	ULONG64 trap_quantity;
	ULONG64 total_execution_time;
	ULONG64 total_dispatch_time;
	ULONG64 total_dispatch_resume_time;

	//For CR3
	CHAR 	cr3_read_write_ctl;
	ULONG64 cr3_write_quantity;
	ULONG64 cr3_read_quantity;
	ULONG64 total_cr3_read_time;
	ULONG64 total_cr3_write_time;
	#endif
} NBP_TRAP,
 *PNBP_TRAP;

/**
 * effects:Build and Initialize General Trap struct (which is also a Trap struct).
 */
NTSTATUS NTAPI TrInitializeGeneralTrap (
  PCPU Cpu,
  ULONG TrappedVmExit,
  UCHAR RipDelta,
  NBP_TRAP_CALLBACK TrapCallback,
  PNBP_TRAP * pInitializedTrap
);

/**
 * effects: Register trap struct.
 */
NTSTATUS NTAPI TrRegisterTrap (
  PCPU Cpu,
  PNBP_TRAP Trap
);
/**
 * Search Registered Traps
 */
NTSTATUS NTAPI TrFindRegisteredTrap (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG exitcode,
  PNBP_TRAP * pTrap
);

NTSTATUS NTAPI TrExecuteGeneralTrapHandler (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);
