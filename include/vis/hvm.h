/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once

#include <ntddk.h>
#include <vis/vcpu.h>
#include <asm/regs.h>
#include <arch/vmx/ept.h>

#define VIS_EXIT_FN		200
#define HOST_STACK_SIZE_IN_PAGES	16

#define BP_GDT_LIMIT	        0x6f
#define BP_IDT_LIMIT	        0xfff

/* Since we record Intel/AMD's VT feature in a condensed 
manner, it is required to use (ARCH_VMX | ARCH_EPT) to check the EPT support, instead of using ARCH_EPT flag only. */
/* <hvm_arch.archtecture> field layout */
/*      Bit 31(63): Vmx/SVM 
        Bit 30: NoHAP/EPT(NPT) 
        Bit 29: NoVPID/VPID(ASID)*/
#define ARCH_shift(idx)       (BITS_PER_LONG - (idx))
#define ARCH_mask(x, idx)     (x ## UL << ARCH_shift(idx))

/* HVM Technology: AMD or Intel? */
#define ARCH_VMX        PG_mask(0, 1) 
#define ARCH_SVM        PG_mask(1, 1)

/* HAP support (EPT/NPT) */
#define ARCH_NO_HAP     PG_mask(0, 2) 
#define ARCH_EPT        PG_mask(1, 2)
#define ARCH_NPT        PG_mask(1, 2)

/* VPID support (VPID/ASID) */
#define ARCH_NO_VPID     PG_mask(0, 3) 
#define ARCH_VPID        PG_mask(1, 3)
#define ARCH_ASID        PG_mask(1, 3)

#define paging_mode_ept(_arch) ((_arch)->hvm.architecture & (ARCH_VMX | ARCH_EPT))

typedef BOOLEAN (NTAPI * ARCH_IS_HVM_IMPLEMENTED) (
);

typedef VOID (NTAPI * ARCH_REGISTER_FEATURES) (
	struct arch_phy* arch
);

typedef NTSTATUS (NTAPI * ARCH_INITIALIZE) (
  	PCPU Cpu,
  	PVOID GuestERip,
  	PVOID GuestEsp
);

typedef NTSTATUS (NTAPI * ARCH_VIRTUALIZE) (
  	PCPU Cpu
);

typedef NTSTATUS (NTAPI * ARCH_SHUTDOWN) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  BOOLEAN bSetupTimeBomb
);

typedef VOID (NTAPI * ARCH_DISPATCH_EVENT) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

typedef VOID (NTAPI * ARCH_ADJUST_RIP) (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG Delta
);

typedef NTSTATUS (NTAPI * ARCH_REGISTER_TRAPS) (
  PCPU Cpu,
  struct arch_phy* arch
);

typedef BOOLEAN (NTAPI * ARCH_IS_TRAP_VALID) (
  ULONG TrappedVmExit
);                              //add by cini


typedef struct
{
    ARCH_IS_HVM_IMPLEMENTED ArchIsHvmImplemented;
    ARCH_REGISTER_FEATURES ArchRegisterFeatures;
    ARCH_INITIALIZE ArchInitialize;
    ARCH_VIRTUALIZE ArchVirtualize;
    ARCH_SHUTDOWN ArchShutdown;
    ARCH_DISPATCH_EVENT ArchDispatchEvent;
    ARCH_ADJUST_RIP ArchAdjustRip;
    ARCH_REGISTER_TRAPS ArchRegisterTraps;
    ARCH_IS_TRAP_VALID ArchIsTrapValid;
} HVM_DEPENDENT,
 *PHVM_DEPENDENT;

extern PHVM_DEPENDENT Hvm;
extern HVM_DEPENDENT Vmx;

struct hvm_arch
{
    ULONG architecture;
	ept_control ept_ctl;
};

/**
 * effects: install our VM root hypervisor on the fly.
 */
NTSTATUS NTAPI HvmSwallowBluepill(void);

/**
 * effects:Uninstall Vis
 */
NTSTATUS NTAPI HvmSpitOutBluepill(void);

/**
 * Check if this cpu supports HVM Technology.
 */
NTSTATUS NTAPI hvm_init(struct arch_phy* arch);
