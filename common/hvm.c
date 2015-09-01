/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#include <vis/hvm.h>
#include <vis/types.h>
#include <vis/mm.h>
#include <vis/arch.h>
#include <asm/system.h>
#include <arch/msr.h>
#include "common.h"

static KMUTEX g_HvmMutex;

ULONG g_uSubvertedCPUs = 0;
PHVM_DEPENDENT Hvm;
struct arch_phy* arch = NULL;

static NTSTATUS _HvmSetupGdt (
    PCPU Cpu
);

static NTSTATUS _HvmSetupIdt (
    PCPU Cpu
);

static NTSTATUS NTAPI HvmLiberateCpu (
    PVOID Param
);

NTSTATUS NTAPI HvmSpitOutBluepill (
)
{
	#ifndef ENABLE_HYPERCALLS
		return STATUS_NOT_SUPPORTED;
	#else

	CCHAR cProcessorNumber;
	NTSTATUS Status, CallbackStatus;

	//g_bDisableComOutput = TRUE;

	Print(("HelloWorld:HvmSpitOutBluepill(): Going to liberate %d processor%s\n",
		 KeNumberProcessors, KeNumberProcessors == 1 ? "" : "s"));

	KeWaitForSingleObject (&g_HvmMutex, Executive, KernelMode, FALSE, NULL);

	for (cProcessorNumber = 0; cProcessorNumber < KeNumberProcessors; cProcessorNumber++) {

		Print(("HelloWorld:HvmSpitOutBluepill(): Liberating processor #%d\n", cProcessorNumber));

		Status = CmDeliverToProcessor (cProcessorNumber, HvmLiberateCpu, NULL, &CallbackStatus);

		if (!NT_SUCCESS (Status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 
					DPFLTR_ERROR_LEVEL,
				"HelloWorld:HvmSpitOutBluepill(): CmDeliverToProcessor() failed with status 0x%08hX\n", Status));
		}

		if (!NT_SUCCESS (CallbackStatus)) {
			Print(("HelloWorld:HvmSpitOutBluepill(): HvmLiberateCpu() failed with status 0x%08hX\n", CallbackStatus));
		}
	}

	Print(("HelloWorld:HvmSpitOutBluepill(): Finished at irql %d\n", KeGetCurrentIrql ()));

	KeReleaseMutex (&g_HvmMutex, FALSE);
	return STATUS_SUCCESS;
	#endif
}


/**
 * effects: install Vis on the fly.
 */
NTSTATUS NTAPI HvmSwallowBluepill()
{//SAME
	CCHAR cProcessorNumber;
	NTSTATUS Status, CallbackStatus;

	Print(("HelloWorld:HvmSwallowBluepill(): Going to subvert %d processor%s\n",
			 KeNumberProcessors, KeNumberProcessors == 1 ? "" : "s"));

	KeWaitForSingleObject (&g_HvmMutex, Executive, KernelMode, FALSE, NULL);

	for (cProcessorNumber = 0; cProcessorNumber < KeNumberProcessors; cProcessorNumber++) 
	{
		Print(("HelloWorld:HvmSwallowBluepill():Installing HelloWorld VT Root Manager on processor #%d\n", cProcessorNumber));

		Status = CmDeliverToProcessor(cProcessorNumber, CmSubvert, NULL, &CallbackStatus);

		if (!NT_SUCCESS (Status)) {
			Print(("HelloWorld:HvmSwallowBluepill(): CmDeliverToProcessor() failed with status 0x%08hX\n", Status));
			KeReleaseMutex (&g_HvmMutex, FALSE);

			HvmSpitOutBluepill ();

			return Status;
		}

		if (!NT_SUCCESS (CallbackStatus)) {
			Print(("HelloWorld:HvmSwallowBluepill(): HvmSubvertCpu() failed with status 0x%08hX\n", CallbackStatus));
			KeReleaseMutex (&g_HvmMutex, FALSE);

			HvmSpitOutBluepill ();

			return CallbackStatus;
		}
	}

	KeReleaseMutex (&g_HvmMutex, FALSE);

	if (KeNumberProcessors != g_uSubvertedCPUs) {
		HvmSpitOutBluepill ();
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

/**
 * Check if this cpu supports Intel VT Technology.
 */
NTSTATUS NTAPI hvm_init(struct arch_phy* parch)
{
	BOOLEAN ArchIsOK = FALSE;

	arch = parch;
	// [TODO] Need refactoring to support SVM
	Hvm = &Vmx;
    ArchIsOK = Hvm->ArchIsHvmImplemented ();
	if (!ArchIsOK) {
		return STATUS_NOT_SUPPORTED;
	} else {
		print("HvmInit():Intel VT-x Supported\n");
		arch->hvm.architecture |= ARCH_VMX;
		Hvm->ArchRegisterFeatures(arch);
	}
	
	KeInitializeMutex (&g_HvmMutex, 0);

	return STATUS_SUCCESS;
}
/**
 * Intialize the CPU struct and start VM by invoking VmxVirtualize()
 * requires: a valid <GuestRsp>
 */
NTSTATUS NTAPI HvmSubvertCpu (
    PVOID GuestRsp
)
{ //Finish
        PCPU Cpu;//It will be used as the hypervisor struct.
        gvaddr_t HostKernelStackBase;
        NTSTATUS Status;
        gpaddr_t HostStackPA;
		ULONG i;

        Print(("HvmSubvertCpu(): Running on processor #%d\n", KeGetCurrentProcessorNumber()));
	

    // allocate memory for host stack, 16 * 4k
    HostKernelStackBase = MmAllocatePages(HOST_STACK_SIZE_IN_PAGES, &HostStackPA, TRUE);
    //HostKernelStackBase = MmAllocateContiguousPages(HOST_STACK_SIZE_IN_PAGES, &HostStackPA, TRUE);
    if (!HostKernelStackBase) 
    {
        Print(("HvmSubvertCpu(): Failed to allocate %d pages for the host stack\n", HOST_STACK_SIZE_IN_PAGES));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // unchecked -8 or -4 ?
    Cpu = (PCPU) ((PCHAR) HostKernelStackBase + HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE - 4 - sizeof (CPU));
    Cpu->HostStack = HostKernelStackBase;

    // for interrupt handlers which will address CPU through the FS
    Cpu->SelfPointer = Cpu;

    Cpu->ProcessorNumber = KeGetCurrentProcessorNumber();

   // Cpu->Nested = FALSE;

   // InitializeListHead (&Cpu->GeneralTrapsList);
   // InitializeListHead (&Cpu->MsrTrapsList);
   // InitializeListHead (&Cpu->IoTrapsList);
    for(i = 0; i < VMX_EXITS_NUM; i++)
    	InitializeListHead (&Cpu->TrapsList[i]);

    Cpu->GdtArea = (PSEGMENT_DESCRIPTOR)MmAllocatePages (BYTES_TO_PAGES (BP_GDT_LIMIT), 
		NULL, TRUE);//Currently we create our own GDT and IDT area
    if (!Cpu->GdtArea) 
    {
        Print(("HvmSubvertCpu(): Failed to allocate memory for GDT\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Cpu->IdtArea = MmAllocatePages (BYTES_TO_PAGES (BP_IDT_LIMIT), NULL, TRUE);
    if (!Cpu->IdtArea) 
    {
        Print(("HvmSubvertCpu(): Failed to allocate memory for IDT\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = Hvm->ArchRegisterTraps(Cpu, arch);//<----------------3.1 Finish
    if (!NT_SUCCESS (Status)) 
    {
		Print(("HvmSubvertCpu(): Failed to register NewBluePill traps, status 0x%08hX\n", Status));
        return STATUS_UNSUCCESSFUL;
    }

    Status = Hvm->ArchInitialize (Cpu, CmSlipIntoMatrix, GuestRsp);//<----------------3.2 Finish
    if (!NT_SUCCESS (Status)) 
    {
        Print(("HvmSubvertCpu(): ArchInitialize() failed with status 0x%08hX\n", Status));
        return Status;
    }

    InterlockedIncrement (&g_uSubvertedCPUs);

    // no API calls allowed below this point: we have overloaded GDTR and selectors
    // unchecked
    _HvmSetupGdt (Cpu);//<----------------3.3 Finish
    _HvmSetupIdt (Cpu);//<----------------3.4 Finish

#if DEBUG_LEVEL > 1
    Print(("HvmSubvertCpu(): RFLAGS = %#x\n", RegGetRflags ()));
#endif

    Status = Hvm->ArchVirtualize(Cpu);//<----------------3.5 Finish

    // never reached
    InterlockedDecrement (&g_uSubvertedCPUs);
    return Status;
}

NTSTATUS NTAPI HvmResumeGuest (
)
{
    Print(("HvmResumeGuest(): Processor #%d, irql %d in GUEST\n",
        KeGetCurrentProcessorNumber (), 
        KeGetCurrentIrql ()));

    // irql will be lowered in the CmDeliverToProcessor()
    //CmSti();
    return STATUS_SUCCESS;
}

//+++++++++++++++++++++Static Functions++++++++++++++++++++++++

//Must move to x86 architecture.
// unchecked
/**
 * effects: Clone GDT into CPU Struct
 */
static NTSTATUS _HvmSetupGdt (
    PCPU Cpu
)
{	//Finish
    ULONG64 GuestTssBase;
    USHORT GuestTssLimit;
    PSEGMENT_DESCRIPTOR GuestTssDescriptor;

    if (!Cpu || !Cpu->GdtArea)
        return STATUS_INVALID_PARAMETER;

    memcpy (Cpu->GdtArea, (PVOID) GetGdtBase(), GetGdtLimit());

    CmReloadGdtr(Cpu->GdtArea, GetGdtLimit());

    return STATUS_SUCCESS;

//#if DEBUG_LEVEL>2
//    CmDumpGdt ((PUCHAR)GetGdtBase(), 0x67);     //(USHORT)GetGdtLimit());
//#endif
//
//    // set code and stack selectors the same with NT to simplify our unloading
//    CmSetGdtEntry (Cpu->GdtArea,
//        BP_GDT_LIMIT,
//        BP_GDT64_CODE,
//        0, 0, LA_STANDARD | LA_DPL_0 | LA_CODE | LA_PRESENT | LA_READABLE | LA_ACCESSED, HA_LONG);
//
//    // we don't want to have a separate segment for DS and ES. They will be equal to SS.
//    CmSetGdtEntry (Cpu->GdtArea,
//        BP_GDT_LIMIT,
//        BP_GDT64_DATA,
//        0, 0xfffff, LA_STANDARD | LA_DPL_0 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_GRANULARITY | HA_DB);
//
//    // fs
//    CmSetGdtEntry (Cpu->GdtArea,
//        BP_GDT_LIMIT,
//        KGDT64_R3_CMTEB, 0, 0x3c00, LA_STANDARD | LA_DPL_3 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_DB);
//
//    // gs
//    CmSetGdtEntry (Cpu->GdtArea,
//        BP_GDT_LIMIT,
//        KGDT64_R3_DATA,
//        0, 0xfffff, LA_STANDARD | LA_DPL_3 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_GRANULARITY | HA_DB);
//
//    GuestTssDescriptor = (PSEGMENT_DESCRIPTOR) (GetGdtBase () + GetTrSelector ());
//
//    GuestTssBase = GuestTssDescriptor->base0 | GuestTssDescriptor->base1 << 16 | GuestTssDescriptor->base2 << 24;
//    GuestTssLimit = GuestTssDescriptor->limit0 | (GuestTssDescriptor->limit1attr1 & 0xf) << 16;
//    if (GuestTssDescriptor->limit1attr1 & 0x80)
//        // 4096-bit granularity is enabled for this segment, scale the limit
//        GuestTssLimit <<= 12;
//
//    if (!(GuestTssDescriptor->attr0 & 0x10))
//    {
//        GuestTssBase = (*(PULONG64) ((PUCHAR) GuestTssDescriptor + 4)) & 0xffffffffff000000;
//        GuestTssBase |= (*(PULONG32) ((PUCHAR) GuestTssDescriptor + 2)) & 0x00ffffff;
//    }
//#if DEBUG_LEVEL>2
//    CmDumpTSS64 ((PTSS64) GuestTssBase, GuestTssLimit);
//#endif
//
//    MmMapGuestTSS64 ((PTSS64) GuestTssBase, GuestTssLimit);
//
//    // don't need to reload TR - we use 0x40, as in xp/vista.
//    CmSetGdtEntry (Cpu->GdtArea, BP_GDT_LIMIT, BP_GDT64_SYS_TSS, (PVOID) GuestTssBase, GuestTssLimit,     //BP_TSS_LIMIT,
//        LA_BTSS64 | LA_DPL_0 | LA_PRESENT | LA_ACCESSED, 0);
//
//    // so far, we have 5 GDT entries.
//    // 0x10: CODE64         cpl0                                            CS
//    // 0x18: DATA           dpl0                                            DS, ES, SS
//    // 0x28: DATA           dpl3                                            GS
//    // 0x40: Busy TSS64, base is equal to NT TSS    TR
//    // 0x50: DATA           dpl3                                            FS
//
//#if DEBUG_LEVEL>2
//    CmDumpGdt ((PUCHAR) Cpu->GdtArea, BP_GDT_LIMIT);
//#endif
//
//    CmReloadGdtr (Cpu->GdtArea, BP_GDT_LIMIT);
//
//    // set new DS and ES
//    CmSetBluepillESDS ();
//
//    // we will use GS as our PCR pointer; GS base will be set to the Cpu in HvmEventCallback
//    // FIXME: but it is not?
//
//    return STATUS_SUCCESS;
}

/**
 * effects: Clone IDT into CPU Struct
 */
static NTSTATUS _HvmSetupIdt (
    PCPU Cpu
)
{
    UCHAR i;

    if (!Cpu || !Cpu->IdtArea)
        return STATUS_INVALID_PARAMETER;

    memcpy ((PVOID)Cpu->IdtArea, (PVOID) GetIdtBase(), GetIdtLimit());

    // just use the system IDT?
    //for (i = 0; i < 255; i++)
    //{
    //    CmSetIdtEntry(
    //        Cpu->IdtArea, 
    //        BP_IDT_LIMIT, 
    //        0x0d,    // #GP
    //        BP_GDT64_CODE, 
    //        InGeneralProtection, 
    //        0, 
    //        LA_PRESENT | LA_DPL_0 | LA_INTGATE64);
    //}

    CmReloadIdtr((PVOID)Cpu->IdtArea, GetIdtLimit());

    return STATUS_SUCCESS;
}
/**
 * effects: Uninstall Vis Hypervisor
 */
static NTSTATUS NTAPI HvmLiberateCpu (
    PVOID Param
)
{ //Finish
  NTSTATUS Status;
  ULONG64 Efer;
  PCPU Cpu;

  // called at DPC level

  if (KeGetCurrentIrql () != DISPATCH_LEVEL)
    return STATUS_UNSUCCESSFUL;

  Efer = MsrRead (MSR_EFER);

  Print(("Vis:HvmLiberateCpu(): Reading MSR_EFER on entry: 0x%X\n", Efer));

  // cause VMM destruction
  RegSetCr3(VIS_EXIT_FN);

  Efer = MsrRead (MSR_EFER);
  Print(("Vis:HvmLiberateCpu(): Reading MSR_EFER on exit: 0x%X\n", Efer));

  return STATUS_SUCCESS;
}

// this function is invoked when guest => host
VOID NTAPI HvmEventCallback (
    PCPU Cpu,                   // cpu struct
    PGUEST_REGS GuestRegs       // store guest's regs
)
{
    NTSTATUS Status;

    if (!Cpu || !GuestRegs)
        return;

    Hvm->ArchDispatchEvent (Cpu, GuestRegs);

    return;
}
