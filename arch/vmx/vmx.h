/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once

#include <ntddk.h>
#include <asm/cpuid.h>
#include <vis/hvm.h>
#include <arch/processor.h>
#include <arch/msr.h>
#include <arch/vmx/vmcs.h>
#include <arch/vmx/vmx.h>

#define	VMX_VMCS_SIZE_IN_PAGES	1
#define	VMX_MSRBitmap_SIZE_IN_PAGES	1
#define	VMX_IOBitmapA_SIZE_IN_PAGES	1
#define	VMX_IOBitmapB_SIZE_IN_PAGES	1
#define	VMX_VMXONR_SIZE_IN_PAGES	2

typedef enum SEGREGS
{
        ES = 0,
        CS,
        SS,
        DS,
        FS,
        GS,
        LDTR,
        TR
};

/*
 * Exit Qualifications for MOV for Control Register Access
 */
#define CONTROL_REG_ACCESS_NUM          0xf     /* 3:0, number of control register */
#define CONTROL_REG_ACCESS_TYPE         0x30    /* 5:4, access type */
#define CONTROL_REG_ACCESS_REG          0xf00   /* 10:8, general purpose register */
#define LMSW_SOURCE_DATA                (0xFFFF << 16)  /* 16:31 lmsw source */

/* XXX these are really VMX specific */
#define TYPE_MOV_TO_DR          (0 << 4)
#define TYPE_MOV_FROM_DR        (1 << 4)
#define TYPE_MOV_TO_CR          (0 << 4)
#define TYPE_MOV_FROM_CR        (1 << 4)
#define TYPE_CLTS               (2 << 4)
#define TYPE_LMSW               (3 << 4)


//+++++++++++++++++++++Structs++++++++++++++++++++++++++++++++

//Implemented in vmx-asm.asm
ULONG NTAPI get_cr4 (
);

VOID NTAPI set_in_cr4 (
  ULONG32 mask
);

VOID NTAPI clear_in_cr4 (
  ULONG32 mask
);

VOID NTAPI VmxVmCall (
  ULONG32 HypercallNumber
);

VOID NTAPI VmxVmexitHandler (
  VOID
);


/**
 * effects:	Check if Intel VT Technology is implemented in this CPU
 *			return false if not, otherwise true.
 **/
static BOOLEAN NTAPI VmxIsImplemented();

static VOID NTAPI vmx_register_features(
	struct arch_phy* arch
);

/**
 * effects: Initialize the guest VM with the callback eip and the esp
 */
static NTSTATUS NTAPI VmxInitialize (
  PCPU Cpu,
  PVOID GuestEip,//points to the next instruction in the guest os.
  PVOID GuestEsp //points to the guest environment-protection register file.
);
/**
 * effects:Start guest VM
 */
static NTSTATUS NTAPI VmxVirtualize (
  	PCPU Cpu
);

/**
 * effects: Check if the VM Exit trap is valid by <TrappedVmExit> value
 * If <TrappedVmExit> >VMX_MAX_GUEST_VMEXIT(43),return false, otherwise true.
 * requires: a valid <TrappedVmExit>
 */
static BOOLEAN NTAPI VmxIsTrapVaild (
  ULONG TrappedVmExit
);
/**
 * effects: Enable the VMX and turn on the VMX
 * thus we are in the VM Root from now on (on this processor).
 */
NTSTATUS NTAPI VmxEnable (
    gvaddr_t VmxonVA
);

NTSTATUS NTAPI VmxDisable (
);

VOID NTAPI VmxCrash (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

VOID DumpMemory (
  PUCHAR Addr,
  ULONG64 Len
);

VOID NTAPI VmxDumpVmcs (
);

//+++++++++++++++++++++Static Functions++++++++++++++++++++++++

/**
 * effects: Build the VMCS struct.
 */
static NTSTATUS VmxSetupVMCS (
    PCPU Cpu,
    PVOID GuestEip,
    PVOID GuestEsp
);

// make the ctl code legal
static ULONG32 NTAPI VmxAdjustControls (
    ULONG32 Ctl,
    ULONG32 Msr
);

static NTSTATUS NTAPI VmxFillGuestSelectorData (
    PVOID GdtBase,
    ULONG Segreg,
    USHORT Selector
);

/**
 * VM Exit Event Dispatcher
 */
static VOID NTAPI VmxDispatchEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);
/**
 * Adjust Rip
 */
static VOID NTAPI VmxAdjustRip (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG Delta
);

/**
 * Shutdown VM
 */
static NTSTATUS NTAPI VmxShutdown (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  BOOLEAN bSetupTimeBomb
);

