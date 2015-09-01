/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once

/* EFER bits: */
#define _EFER_SCE		0  /* SYSCALL/SYSRET */
#define _EFER_LME		8  /* Long mode enable */
#define _EFER_LMA		10 /* Long mode active (read-only) */
#define _EFER_NX		11 /* No execute enable */
#define _EFER_SVME		12 /* AMD: SVM enable */
#define _EFER_LMSLE		13 /* AMD: Long-mode segment limit enable */
#define _EFER_FFXSE		14 /* AMD: Fast FXSAVE/FXRSTOR enable */

#define EFER_SCE		(1<<_EFER_SCE)
#define EFER_LME		(1<<_EFER_LME)
#define EFER_LMA		(1<<_EFER_LMA)
#define EFER_NX			(1<<_EFER_NX)
#define EFER_SVME		(1<<_EFER_SVME)
#define EFER_LMSLE		(1<<_EFER_LMSLE)
#define EFER_FFXSE		(1<<_EFER_FFXSE)

#define MSR_TSC	                0x10
#define MSR_EFER		        0xc0000080
#define MSR_FS_BASE		        0xc0000100
#define MSR_GS_BASE		        0xc0000101
#define MSR_LSTAR		        0xC0000082
#define MSR_SHADOW_GS_BASE	0xc0000102
#define MSR_VM_HSAVE_PA		0xC0010117

/*
 * Intel CPU  MSR
 */
/* MSRs & bits used for VMX enabling */
#define MSR_IA32_FEATURE_CONTROL 				0x03a
#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48b
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490


#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9

#define wrtsc(val) MsrWrite(MSR_TSC, val)

extern ULONG64 NTAPI MsrRead (
        ULONG32 reg
);

extern VOID NTAPI MsrWrite (
        ULONG32 reg,
        ULONG64 MsrValue
);
