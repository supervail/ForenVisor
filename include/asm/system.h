/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once

#define REG_MASK			0x07

#define REG_GP				0x08
#define REG_GP_ADDITIONAL	0x10
#define REG_CONTROL			0x20
#define REG_DEBUG			0x40
#define REG_RFLAGS			0x80

#define REG_RAX	REG_GP | 0
#define REG_RCX	REG_GP | 1
#define REG_RDX	REG_GP | 2
#define REG_RBX	REG_GP | 3
#define REG_RSP	REG_GP | 4
#define REG_RBP	REG_GP | 5
#define REG_RSI	REG_GP | 6
#define REG_RDI	REG_GP | 7

#define REG_CR0	REG_CONTROL | 0
#define REG_CR2	REG_CONTROL | 2
#define REG_CR3	REG_CONTROL | 3
#define REG_CR4	REG_CONTROL | 4

VOID NTAPI CmCli (
);

VOID NTAPI CmSti (
);

VOID NTAPI CmDebugBreak (
);

VOID NTAPI CmWbinvd (
);

VOID NTAPI CmClflush (
  PVOID mem8
);

VOID NTAPI CmInvalidatePage (
  PVOID Page
);

VOID NTAPI CmReloadGdtr (
  PVOID GdtBase,
  ULONG GdtLimit
);

VOID NTAPI CmReloadIdtr (
  PVOID IdtBase,
  ULONG IdtLimit
);

NTSTATUS NTAPI CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG Value
);

NTSTATUS NTAPI CmGeneratePushReg (
    PUCHAR pCode,
    PULONG pGeneratedCodeLength,
    ULONG Register
);

NTSTATUS NTAPI CmGenerateIretd (
    PUCHAR pCode,
    PULONG pGeneratedCodeLength
);