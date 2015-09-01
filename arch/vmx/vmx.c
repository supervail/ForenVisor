/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
					Add performance metric functions and enable EPT support.
* 
*****************************/

#include <vis/config.h>
#include <vis/mm.h>
#include <vis/ppt.h>
#include <vis/traps.h>
#include <vis/arch.h>
#include <asm/system.h>
#include "vmx.h"
#include "vmxtraps.h"
#include <vis/io.h>

#ifdef CONFIG_PERF_ENABLE
#include <vis/perf.h>
#endif

ULONG g_HostStackBaseAddress; //4     // FIXME: this is ugly -- we should move it somewhere else
extern ULONG g_uSubvertedCPUs;
static struct arch_phy* arch;

HVM_DEPENDENT Vmx = {
  VmxIsImplemented,
  vmx_register_features,
  VmxInitialize,
  VmxVirtualize,
  VmxShutdown,
  //VmxIsNestedEvent,
  //VmxDispatchNestedEvent,
  VmxDispatchEvent,
  VmxAdjustRip,
  VmxRegisterTraps,
  VmxIsTrapVaild
};

static ULONG32 NTAPI VmxAdjustControls (
    ULONG32 Ctl,
    ULONG32 Msr
);

static VOID VmxHandleInterception (
    PCPU Cpu,
    PGUEST_REGS GuestRegs
);

/**
 * effects:To see if the indicated bit is set or not.
 * requires: 0<=bitNo<=63
 */
static BOOLEAN CmIsBitSet (
  ULONG64 v,
  UCHAR bitNo
)
{
        ULONG64 mask = (ULONG64) 1 << bitNo;
        return (BOOLEAN) ((v & mask) != 0);
}

/**
 * effects: Check if Intel VT Technology is implemented in this CPU
 * return false if not, otherwise true.
 **/
static BOOLEAN NTAPI VmxIsImplemented()
{
	ULONG32 eax, ebx, ecx, edx;
	GetCpuIdInfo (0, &eax, &ebx, &ecx, &edx);
	if (eax < 1) 
	{
		Print(("VmxIsImplemented(): Extended CPUID functions not implemented\n"));
		return FALSE;
	}
	if (!(ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69)) 
	{
		Print(("VmxIsImplemented(): Not an Intel processor\n"));
		return FALSE;
	}

	// intel cpu use fun_0x1 to test VMX.
	// CPUID.1:ECX.VMX[bit 5] = 1
	GetCpuIdInfo (0x1, &eax, &ebx, &ecx, &edx);
	return (BOOLEAN) (CmIsBitSet (ecx, 5));
}

VOID NTAPI vmx_register_features(struct arch_phy* parch)
{
	ULONG32 _vmx_cpu_based_exec_control, _vmx_secondary_exec_control;
	ULONG32 ctl;

	arch = parch;
	ctl = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	_vmx_cpu_based_exec_control = VmxAdjustControls(
        ctl, MSR_IA32_VMX_PROCBASED_CTLS);

	if ( _vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS )
    {
        ctl = (SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
               SECONDARY_EXEC_WBINVD_EXITING |
               SECONDARY_EXEC_ENABLE_EPT |
               SECONDARY_EXEC_ENABLE_RDTSCP |
               SECONDARY_EXEC_PAUSE_LOOP_EXITING | 
               SECONDARY_EXEC_ENABLE_VPID | 
               SECONDARY_EXEC_UNRESTRICTED_GUEST);

        _vmx_secondary_exec_control = VmxAdjustControls(
            ctl, MSR_IA32_VMX_PROCBASED_CTLS2);
    }

	/* Check EPT Support */
    if ( _vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT )
    {
		arch->hvm.architecture |= ARCH_EPT;
		print("Vmx: Support EPT\n");
    }

	if ( _vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT )
	{
		arch->hvm.architecture |= ARCH_VPID;
		print("Vmx: Support VPID\n");
	}
}


/**
 * effects: Initialize the guest VM with the callback eip and the esp
 */
static NTSTATUS NTAPI VmxInitialize (
    PCPU Cpu,
    PVOID GuestEip,//points to the next instruction in the guest os.
    PVOID GuestEsp //points to the guest environment-protection register file.
)
{
    PHYSICAL_ADDRESS AlignedVmcsPA;
    ULONG VaDelta;
    NTSTATUS Status;

    gvaddr_t tmp = MmAllocateContiguousPages (1, NULL, TRUE);
    g_HostStackBaseAddress = (ULONG) tmp;
    // do not deallocate anything here; MmShutdownManager will take care of that
	
    //Allocate VMXON region
    Cpu->Vmx.OriginaVmxonR = MmAllocateContiguousPages(
        VMX_VMXONR_SIZE_IN_PAGES, 
        &Cpu->Vmx.OriginalVmxonRPA,
        TRUE);
    if (!Cpu->Vmx.OriginaVmxonR) 
    {
		Print(("Helloworld:VmxInitialize(): Failed to allocate memory for original VMCS\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Print(("Helloworld:VmxInitialize(): OriginaVmxonR VA: 0x%x\n", Cpu->Vmx.OriginaVmxonR));
    Print(("Helloworld:VmxInitialize(): OriginaVmxonR PA: 0x%llx\n", Cpu->Vmx.OriginalVmxonRPA));
    //Allocate VMCS	
    Cpu->Vmx.OriginalVmcs = MmAllocateContiguousPages(
        VMX_VMCS_SIZE_IN_PAGES, 
        &Cpu->Vmx.OriginalVmcsPA,
        TRUE);
    if (!Cpu->Vmx.OriginalVmcs) 
    {
		Print(("Helloworld:VmxInitialize(): Failed to allocate memory for original VMCS\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Print(("Helloworld:VmxInitialize(): Vmcs VA: 0x%x\n", Cpu->Vmx.OriginalVmcs));
    Print(("Helloworld:VmxInitialize(): Vmcs PA: 0x%llx\n", Cpu->Vmx.OriginalVmcsPA));

    // these two PAs are equal if there're no nested VMs
    Cpu->Vmx.VmcsToContinuePA = Cpu->Vmx.OriginalVmcsPA;

    Cpu->Vmx.MSRBitmap = MmAllocateContiguousPages(
        VMX_MSRBitmap_SIZE_IN_PAGES, 
        &Cpu->Vmx.MSRBitmapPA,
        TRUE);
    if (!Cpu->Vmx.MSRBitmap) 
    {
        Print(("VmxInitialize(): Failed to allocate memory for  MSRBitmap\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory ((PVOID)Cpu->Vmx.MSRBitmap, PAGE_SIZE);

    Print(("VmxInitialize(): MSRBitmap VA: 0x%x\n", Cpu->Vmx.MSRBitmap));
    Print(("VmxInitialize(): MSRBitmap PA: 0x%llx\n", Cpu->Vmx.MSRBitmapPA));

	// allocate IOBitmap A&B
	Cpu->Vmx.IOBitmapA = MmAllocateContiguousPages(
		VMX_IOBitmapA_SIZE_IN_PAGES, 
		&Cpu->Vmx.IOBitmapAPA,
		TRUE);
	if (!Cpu->Vmx.IOBitmapA) 
	{
		Print(("VmxInitialize(): Failed to allocate memory for	IOBitmapA\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory ((PVOID)Cpu->Vmx.IOBitmapA, PAGE_SIZE);
	// only intercept the keyboard
	set_iobmp(Cpu, KBD_DATA, 1);
	
	Print(("VmxInitialize(): IOBitmapA VA: 0x%x\n", Cpu->Vmx.IOBitmapA));
	Print(("VmxInitialize(): IOBitmapA PA: 0x%llx\n", Cpu->Vmx.IOBitmapAPA));

	Cpu->Vmx.IOBitmapB = MmAllocateContiguousPages(
		VMX_IOBitmapB_SIZE_IN_PAGES, 
		&Cpu->Vmx.IOBitmapBPA,
		TRUE);
	if (!Cpu->Vmx.IOBitmapB) 
	{
		Print(("VmxInitialize(): Failed to allocate memory for	IOBitmapB\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory ((PVOID)Cpu->Vmx.IOBitmapB, PAGE_SIZE);
	
	Print(("VmxInitialize(): IOBitmapA VA: 0x%x\n", Cpu->Vmx.IOBitmapB));
	Print(("VmxInitialize(): IOBitmapA PA: 0x%llx\n", Cpu->Vmx.IOBitmapBPA));

    // call VMXON, should fill the version first
    if (!NT_SUCCESS (VmxEnable (Cpu->Vmx.OriginaVmxonR))) 
    {
        Print( ("Helloworld:VmxInitialize(): Failed to enable Vmx\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // version
    *((ULONG64 *)(Cpu->Vmx.OriginalVmcs)) = 
        (MsrRead (MSR_IA32_VMX_BASIC) & 0xffffffff); //set up vmcs_revision_id      

    // fill the VMCS struct
    Status = VmxSetupVMCS (Cpu, GuestEip, GuestEsp);
    if (!NT_SUCCESS (Status)) 
    {
        Print(("Helloworld:Vmx(): VmxSetupVMCS() failed with status 0x%08hX\n", Status));
        VmxDisable();
        return Status;
    }

    Print(("Helloworld:VmxInitialize(): Vmx enabled\n"));

    Cpu->Vmx.GuestEFER = MsrRead (MSR_EFER);
    Print(("Helloworld:Guest MSR_EFER Read 0x%llx \n", Cpu->Vmx.GuestEFER));

    Cpu->Vmx.GuestCR0 = RegGetCr0 ();
    Cpu->Vmx.GuestCR3 = RegGetCr3 ();
    Cpu->Vmx.GuestCR4 = RegGetCr4 ();

    CmCli ();
    return STATUS_SUCCESS;
}

/**
 * effects:Start the virtual machine
 */
static NTSTATUS NTAPI VmxVirtualize (
  PCPU Cpu
)
{
    ULONG esp;
    if (!Cpu)
        return STATUS_INVALID_PARAMETER;

    Print(("VmxVirtualize(): VmxRead: 0x%X \n", VmxRead (VM_INSTRUCTION_ERROR)));
    Print(("VmxVirtualize(): EFlags before vmxLaunch: 0x%x \n", RegGetRflags ()));
    Print(("VmxVirtualize(): PCPU: 0x%x \n", Cpu));
    esp = RegGetEsp ();
    Print(("VmxVirtualize(): Rsp: 0x%x \n", esp));

//#ifndef _X86_
    *((PULONG) (g_HostStackBaseAddress + 0x0C00)) = (ULONG) Cpu;
//#endif
    
    //Only boot processor can build ept table and private page table. 
    //Other processors just use them.
    if(is_boot_processor(Cpu))
    {
		mm_map_machine_pfns(arch);

		#ifdef CONFIG_USE_PRIVATE_PAGETABLE
			ppt_create();
		#endif
    }

	#ifdef CONFIG_USE_PRIVATE_PAGETABLE
	ppt_monitor_guest_pagetable();
	#endif
	
	//if (KeGetCurrentProcessorNumber() == 0) //Only Boot processor can build ept table. Other processor just uses it.
		//mm_hide_vis_data(arch);

	//DbgPrint("VmxVirtualize(): EPT eptp:0x%llx\n", arch->hvm.ept_ctl.eptp);
    VmxLaunch ();

	//should never returns
	panic(("VmxVirtualize() returns"));

	return STATUS_UNSUCCESSFUL;
}


/**
 * effects: Check if the VM Exit trap is valid by <TrappedVmExit> value
 * If <TrappedVmExit> >VMX_MAX_GUEST_VMEXIT(43),return false, otherwise true.
 * requires: a valid <TrappedVmExit>
 */
static BOOLEAN NTAPI VmxIsTrapVaild (
  ULONG TrappedVmExit
)//Finished
{
  if (TrappedVmExit > VMX_MAX_GUEST_VMEXIT)
    return FALSE;
  return TRUE;
}

/**
 * effects: Enable the VMX and turn on the VMX
 * thus we are in the VM Root from now on (on this processor).
 */
NTSTATUS NTAPI VmxEnable (
    gvaddr_t VmxonVA
)
{
    ULONG cr4;
    ULONG64 vmxmsr;//ULONG32
    ULONG flags;
    PHYSICAL_ADDRESS VmxonPA;

    // set cr4, enable vmx
    set_in_cr4 (X86_CR4_VMXE);
    cr4 = get_cr4 ();
    Print(("Helloworld:VmxEnable(): CR4 after VmxEnable: 0x%llx\n", cr4));
    if (!(cr4 & X86_CR4_VMXE))
        return STATUS_NOT_SUPPORTED;

    // check msr(3ah) bit2
    vmxmsr = MsrRead (MSR_IA32_FEATURE_CONTROL);
    if (!(vmxmsr & 4)) 
    {
        Print(("Helloworld:VmxEnable(): VMX is not supported: IA32_FEATURE_CONTROL is 0x%llx\n", vmxmsr));
        return STATUS_NOT_SUPPORTED;
    }

    vmxmsr = MsrRead (MSR_IA32_VMX_BASIC);
    *((ULONG64 *) VmxonVA) = (vmxmsr & 0xffffffff);       //set up vmcs_revision_id

    VmxonPA = MmGetPhysicalAddress ((PVOID)VmxonVA);
    Print(("Helloworld:VmxEnable(): VmxonPA:  0x%llx\n", VmxonPA.QuadPart));

	VmxTurnOn(VmxonPA);
    flags = RegGetRflags ();
    Print(("Helloworld:VmxEnable(): vmcs_revision_id: 0x%x  Eflags: 0x%x \n", vmxmsr, flags));
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI VmxDisable (
)
{
    ULONG cr4;
    VmxTurnOff ();
    cr4 = get_cr4 ();
    clear_in_cr4 (X86_CR4_VMXE);
    cr4 = get_cr4 ();
    Print(("VmxDisable(): CR4 after VmxDisable: 0x%llx\n", cr4));
    return STATUS_SUCCESS;
}

/**
 * effects: Build the VMCS struct.
 */
static NTSTATUS VmxSetupVMCS (
    PCPU Cpu,
    PVOID GuestEip,
    PVOID GuestEsp
)
{ //Finished
    SEGMENT_SELECTOR SegmentSelector;
    PHYSICAL_ADDRESS VmcsToContinuePA;
    NTSTATUS Status;
    PVOID GdtBase;
    ULONG32 Interceptions;

    if (!Cpu || !Cpu->Vmx.OriginalVmcs)
        return STATUS_INVALID_PARAMETER;

    VmcsToContinuePA.QuadPart = Cpu->Vmx.VmcsToContinuePA;
    // load the vmcs
    VmxClear (VmcsToContinuePA);
    VmxPtrld (VmcsToContinuePA);

    /*16BIT Fields */

    /*16BIT Host-Statel Fields. */
    VmxWrite (HOST_ES_SELECTOR, RegGetEs () & 0xf8);
    VmxWrite (HOST_CS_SELECTOR, RegGetCs () & 0xf8);
    VmxWrite (HOST_SS_SELECTOR, RegGetSs () & 0xf8);
    VmxWrite (HOST_DS_SELECTOR, RegGetDs () & 0xf8);

    VmxWrite (HOST_FS_SELECTOR, (RegGetFs () & 0xf8));
    VmxWrite (HOST_GS_SELECTOR, (RegGetGs () & 0xf8));
    VmxWrite (HOST_TR_SELECTOR, (GetTrSelector () & 0xf8));

    ///*64BIT Control Fields. */
    VmxWrite (IO_BITMAP_A, (ULONG32)Cpu->Vmx.IOBitmapAPA);
    VmxWrite (IO_BITMAP_B, (ULONG32)Cpu->Vmx.IOBitmapBPA);

    // FIXME???
    //*(((unsigned char*)(Cpu->Vmx.IOBitmapB))+((0xc880-0x8000)/8))=0xff;  //0xc880-0xc887  
#if defined (_X64_)
    VmxWrite (IO_BITMAP_A_HIGH, Cpu->Vmx.IOBitmapBPA >> 32);
    VmxWrite (IO_BITMAP_B_HIGH, Cpu->Vmx.IOBitmapBPA >> 32);
#endif

    VmxWrite (MSR_BITMAP, (ULONG32)Cpu->Vmx.MSRBitmapPA); //Cpu->Vmx.MSRBitmapPA.LowPart
#if defined (_X64_)
    VmxWrite (MSR_BITMAP_HIGH, Cpu->Vmx.MSRBitmapPA >> 32); //Cpu->Vmx.MSRBitmapPA.HighPart
#endif

    //VM_EXIT_MSR_STORE_ADDR          = 0x00002006,  //no init
    //VM_EXIT_MSR_STORE_ADDR_HIGH     = 0x00002007,  //no init
    //VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,  //no init
    //VM_EXIT_MSR_LOAD_ADDR_HIGH      = 0x00002009,  //no init
    //VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,  //no init
    //VM_ENTRY_MSR_LOAD_ADDR_HIGH     = 0x0000200b,  //no init

   /* VmxWrite (TSC_OFFSET, 0);
    VmxWrite (TSC_OFFSET_HIGH, 0);*/

    //VIRTUAL_APIC_PAGE_ADDR          = 0x00002012,   //no init
    //VIRTUAL_APIC_PAGE_ADDR_HIGH     = 0x00002013,   //no init

    /*64BIT Guest-State Fields. */
    VmxWrite (VMCS_LINK_POINTER, 0xffffffff);
    VmxWrite (VMCS_LINK_POINTER_HIGH, 0xffffffff);

    VmxWrite (GUEST_IA32_DEBUGCTL, MsrRead (MSR_IA32_DEBUGCTL) & 0xffffffff);
    VmxWrite (GUEST_IA32_DEBUGCTL_HIGH, MsrRead (MSR_IA32_DEBUGCTL) >> 32);

    /*32BIT Control Fields. */
    //disable Vmexit by Extern-interrupt,NMI and Virtual NMI
    // Pin-based VM-execution controls
    VmxWrite (PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls (0, MSR_IA32_VMX_PINBASED_CTLS));//<------------------5.1 Finished

	// Primary processor-based VM-execution controls
    Interceptions = CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_IO_BITMAP
		| CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    Interceptions = VmxAdjustControls (Interceptions, 
		MSR_IA32_VMX_PROCBASED_CTLS);
    VmxWrite (CPU_BASED_VM_EXEC_CONTROL, Interceptions);

	if(paging_mode_ept(arch))
	{
		Interceptions = SECONDARY_EXEC_ENABLE_EPT;
		Interceptions = VmxAdjustControls(Interceptions, 
			MSR_IA32_VMX_PROCBASED_CTLS2);
		VmxWrite(SECONDARY_VM_EXEC_CONTROL, Interceptions);
	}	

    VmxWrite (EXCEPTION_BITMAP, (ULONG)1 << 14);

    //VmxWrite (PAGE_FAULT_ERROR_CODE_MASK, 2);   // W/R
    //VmxWrite (PAGE_FAULT_ERROR_CODE_MATCH, 2);  // write cause the fault
    VmxWrite (PAGE_FAULT_ERROR_CODE_MASK, 0);
    VmxWrite (PAGE_FAULT_ERROR_CODE_MATCH, 0xFFFFFFFF);

    VmxWrite (CR3_TARGET_COUNT, 0);

    // VM-exit controls
    // bit 15, Acknowledge interrupt on exit
    VmxWrite (VM_EXIT_CONTROLS, 
        VmxAdjustControls (VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    // VM-entry controls
    VmxWrite (VM_ENTRY_CONTROLS, 
        VmxAdjustControls (0, MSR_IA32_VMX_ENTRY_CTLS));

    VmxWrite (VM_EXIT_MSR_STORE_COUNT, 0);
    VmxWrite (VM_EXIT_MSR_LOAD_COUNT, 0);

    VmxWrite (VM_ENTRY_MSR_LOAD_COUNT, 0);
    VmxWrite (VM_ENTRY_INTR_INFO, 0);

    //VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018,  //no init
    //VM_ENTRY_INSTRUCTION_LEN        = 0x0000401a,  //no init
    //TPR_THRESHOLD                   = 0x0000401c,  //no init

    /*32BIT Read-only Fields:need no setup */

    /*32BIT Guest-Statel Fields. */

    VmxWrite (GUEST_GDTR_LIMIT, GetGdtLimit ());
    VmxWrite (GUEST_IDTR_LIMIT, GetIdtLimit ());

    VmxWrite (GUEST_INTERRUPTIBILITY_INFO, 0);
    VmxWrite (GUEST_ACTIVITY_STATE, 0);   //Active state          
    //GUEST_SM_BASE          = 0x98000,   //no init
    VmxWrite (GUEST_SYSENTER_CS, MsrRead (MSR_IA32_SYSENTER_CS));

    /*32BIT Host-Statel Fields. */

    VmxWrite (HOST_SYSENTER_CS, MsrRead (MSR_IA32_SYSENTER_CS));     //no use

    /* NATURAL Control State Fields:need not setup. */
    // CR0 guest/host mask
    //VmxWrite (CR0_GUEST_HOST_MASK, X86_CR0_PG);   //X86_CR0_WP
    VmxWrite (CR0_GUEST_HOST_MASK, 0);
    // CR0 read shadow
    //VmxWrite (CR0_READ_SHADOW, (RegGetCr4 () & X86_CR0_PG) | X86_CR0_PG);
    // if PG is clear, a vmexit will be caused
    VmxWrite (CR0_READ_SHADOW, 0);

    //VmxWrite(CR4_GUEST_HOST_MASK, X86_CR4_VMXE|X86_CR4_PAE|X86_CR4_PSE);
    // disable vmexit 0f mov to cr4 expect for X86_CR4_VMXE
    VmxWrite (CR4_GUEST_HOST_MASK, 0); 
    VmxWrite (CR4_READ_SHADOW, 0);

    // CR3_TARGET_COUNT is 0, mov to CR3 always cause a vmexit
    VmxWrite (CR3_TARGET_VALUE0, 0);      //no use
    VmxWrite (CR3_TARGET_VALUE1, 0);      //no use                        
    VmxWrite (CR3_TARGET_VALUE2, 0);      //no use
    VmxWrite (CR3_TARGET_VALUE3, 0);      //no use

	if ( paging_mode_ept(arch))
    {
        VmxWrite(EPT_POINTER, arch->hvm.ept_ctl.eptp);
		#ifdef _X86_
        VmxWrite(EPT_POINTER_HIGH, arch->hvm.ept_ctl.eptp >> 32);
		#endif
    }
	 
    /* NATURAL Read-only State Fields:need not setup. */

    /* NATURAL GUEST State Fields. */

    VmxWrite (GUEST_CR0, RegGetCr0 ());
    VmxWrite (GUEST_CR3, RegGetCr3 ());
    VmxWrite (GUEST_CR4, RegGetCr4 ());

    GdtBase = (PVOID) GetGdtBase ();

    // Setup guest selectors
    VmxFillGuestSelectorData (GdtBase, ES, RegGetEs ());
    VmxFillGuestSelectorData (GdtBase, CS, RegGetCs ());
    VmxFillGuestSelectorData (GdtBase, SS, RegGetSs ());
    VmxFillGuestSelectorData (GdtBase, DS, RegGetDs ());
    VmxFillGuestSelectorData (GdtBase, FS, RegGetFs ());
    VmxFillGuestSelectorData (GdtBase, GS, RegGetGs ());
    VmxFillGuestSelectorData (GdtBase, LDTR, GetLdtr ());
    VmxFillGuestSelectorData (GdtBase, TR, GetTrSelector ());

    // LDTR/TR bases have been set in VmxFillGuestSelectorData()
    VmxWrite (GUEST_GDTR_BASE, (ULONG) GdtBase);
    VmxWrite (GUEST_IDTR_BASE, GetIdtBase ());

    VmxWrite (GUEST_DR7, 0x400);
    VmxWrite (GUEST_RSP, (ULONG) GuestEsp);     //setup guest sp
    VmxWrite (GUEST_RIP, (ULONG) GuestEip);     //setup guest ip:CmSlipIntoMatrix
    VmxWrite (GUEST_RFLAGS, RegGetRflags ());
    //VmxWrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);//no init
    VmxWrite (GUEST_SYSENTER_ESP, (ULONG)MsrRead (MSR_IA32_SYSENTER_ESP));
    VmxWrite (GUEST_SYSENTER_EIP, (ULONG)MsrRead (MSR_IA32_SYSENTER_EIP));

    /* HOST State Fields. */
    VmxWrite (HOST_CR0, RegGetCr0 ());

#ifdef CONFIG_USE_PRIVATE_PAGETABLE
    // private cr3
    VmxWrite (HOST_CR3, gfn_to_gpaddr(arch->private_table));
#else
    VmxWrite (HOST_CR3, RegGetCr3 ());
#endif
    VmxWrite (HOST_CR4, RegGetCr4 ());

    // unchecked
    //VmxWrite (HOST_FS_BASE, MsrRead (MSR_FS_BASE));
    //VmxWrite (HOST_GS_BASE, MsrRead (MSR_GS_BASE));
	//We only handle FS and GS segment here
    CmInitializeSegmentSelector (&SegmentSelector, RegGetFs (), (PVOID) GetGdtBase ());//<----------------------5.3 Finish
    VmxWrite (HOST_FS_BASE, SegmentSelector.base);

    CmInitializeSegmentSelector (&SegmentSelector, RegGetGs (), (PVOID) GetGdtBase ());
    VmxWrite (HOST_GS_BASE, SegmentSelector.base);

    // TODO: we must setup our own TSS
    // FIXME???

    CmInitializeSegmentSelector (&SegmentSelector, GetTrSelector (), (PVOID) GetGdtBase ());
    VmxWrite (HOST_TR_BASE, SegmentSelector.base);

    // unchecked
    //VmxWrite (HOST_GDTR_BASE, (ULONG64) Cpu->GdtArea);
    //VmxWrite (HOST_IDTR_BASE, (ULONG64) Cpu->IdtArea);

    // FIXME???
    VmxWrite(HOST_GDTR_BASE, GetGdtBase());
    VmxWrite(HOST_IDTR_BASE, GetIdtBase());

    VmxWrite (HOST_SYSENTER_ESP, (ULONG)MsrRead (MSR_IA32_SYSENTER_ESP));
    VmxWrite (HOST_SYSENTER_EIP, (ULONG)MsrRead (MSR_IA32_SYSENTER_EIP));

    VmxWrite (HOST_RSP, g_HostStackBaseAddress + 0x0C00); //setup host sp at vmxLaunch(...)

    VmxWrite (HOST_RIP, (ULONG) VmxVmexitHandler); //setup host ip:CmSlipIntoMatrix

	Print(("Helloworld:VmxSetupVMCS(): Exit\n"));

    return STATUS_SUCCESS;
}
/**
 * effects: Fill guest segment selectors fields in VMCS
 */
static NTSTATUS NTAPI VmxFillGuestSelectorData (
    PVOID GdtBase,
    ULONG Segreg,//use the element in enum SEGREGS
    USHORT Selector
)
{//Finished
    SEGMENT_SELECTOR SegmentSelector = {0};
    ULONG uAccessRights;
    CmInitializeSegmentSelector (&SegmentSelector, Selector, GdtBase);//<--------------------6.1 Finished
    uAccessRights = 
        ((PUCHAR)&SegmentSelector.attributes)[0] + (((PUCHAR)&SegmentSelector.attributes)[1] << 12);

    if (!Selector)
        uAccessRights |= 0x10000;

    VmxWrite (GUEST_ES_SELECTOR + Segreg * 2, Selector);
    VmxWrite (GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.limit);
    VmxWrite (GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);

    //if ((Segreg == LDTR) || (Segreg == TR))
    {
        // don't setup for FS/GS - their bases are stored in MSR values
        // for x64?
        VmxWrite (GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);
    }

    return STATUS_SUCCESS;
}

// make the ctl code legal
static ULONG32 NTAPI VmxAdjustControls (
    ULONG32 Ctl,
    ULONG32 Msr
)
{//Finished
    LARGE_INTEGER MsrValue;

    MsrValue.QuadPart = MsrRead (Msr);
    Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

static ULONG64 rdtsc()
{
	__asm {rdtsc}
}


static VOID NTAPI _save_guest_regs(PCPU Cpu, PGUEST_REGS GuestRegs)
{
	GuestRegs->esp = VmxRead (GUEST_RSP);
	GuestRegs->eflags = VmxRead(GUEST_RFLAGS);
	
	#ifdef CONFIG_RESTORE_GUEST_TSC
		Cpu->guest_current_tsc = rdtsc();
	#endif
}
static VOID NTAPI _restore_guest_regs(PCPU Cpu, PGUEST_REGS GuestRegs)
{
	VmxWrite (GUEST_RSP, GuestRegs->esp);
	VmxWrite (GUEST_RFLAGS, GuestRegs->eflags);
	
	#ifdef CONFIG_RESTORE_GUEST_TSC
		wrtsc(Cpu->guest_current_tsc);
	#endif
}

#ifdef CONFIG_PERF_ENABLE
static VOID NTAPI _perf_switch_to_hypervisor(PCPU cpu)
{
	cpu->total_guest_time+=perf_get_execution_time(cpu->last_guest_start_tsc);
	cpu->switch_to_hypervisor_quantity++;

	//perf ctr field re-initialization
	cpu->ctl_measure_vmresume = 0;
	
	
	cpu->last_hypervisor_start_tsc = perf_start_timer();
}
static VOID NTAPI _perf_switch_to_guest(PCPU cpu, PGUEST_REGS GuestRegs)
{
	cpu->total_hypervisor_time += perf_get_execution_time(cpu->last_hypervisor_start_tsc);
	cpu->switch_to_guest_quantity++;

	if(cpu->ctl_measure_vmresume == 1)
	{
		ULONG64 vmresume_tsc = rdtsc();

		GuestRegs->edx = u64high_to_u32(vmresume_tsc);
		GuestRegs->eax = u64low_to_u32(vmresume_tsc);
	}

	
	cpu->last_guest_start_tsc = perf_start_timer();
}
#endif


/**
 * VM Exit Event Dispatcher
 */
static VOID NTAPI VmxDispatchEvent (
    PCPU Cpu,
    PGUEST_REGS GuestRegs
)
{
	#ifdef CONFIG_PERF_ENABLE
	_perf_switch_to_hypervisor(Cpu);
	#endif
	
	_save_guest_regs(Cpu, GuestRegs);

  	VmxHandleInterception(
      	Cpu, 
      	GuestRegs
    );
	_restore_guest_regs(Cpu, GuestRegs);

	#ifdef CONFIG_PERF_ENABLE
	_perf_switch_to_guest(Cpu, GuestRegs);
	#endif
}
static VOID VmxGenerateTrampolineToGuest (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PUCHAR Trampoline,
  BOOLEAN bSetupTimeBomb
)
{
  ULONG uTrampolineSize = 0;
  ULONG NewRsp;

  if (!Cpu || !GuestRegs)
    return;

  // assume Trampoline buffer is big enough


  VmxWrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & ~0x100);     // disable TF

  if (bSetupTimeBomb) 
  {
  } 
  else 
  {
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RCX, GuestRegs->ecx);
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDX, GuestRegs->edx);
  }

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBX, GuestRegs->ebx);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBP, GuestRegs->ebp);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSI, GuestRegs->esi);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDI, GuestRegs->edi);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR0, VmxRead (GUEST_CR0));
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR3, VmxRead (GUEST_CR3));
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR4, VmxRead (GUEST_CR4));

  NewRsp = VmxRead (GUEST_RSP);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSP, NewRsp);

  // construct stack frame for IRETQ:
  // [TOS]        rip
  // [TOS+0x08]   cs
  // [TOS+0x10]   rflags
  // [TOS+0x18]   rsp
  // [TOS+0x20]   ss

  // construct stack frame for IRETD:
  // [TOS]        rip
  // [TOS+0x4]    cs
  // [TOS+0x8]    rflags

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_RFLAGS));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_CS_SELECTOR));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);

  if (bSetupTimeBomb) 
  {
  } 
  else 
  {
    CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX,
                      VmxRead (GUEST_RIP) + VmxRead (VM_EXIT_INSTRUCTION_LEN));
  }

  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, GuestRegs->eax);

  CmGenerateIretd (&Trampoline[uTrampolineSize], &uTrampolineSize);

  // restore old GDTR
  CmReloadGdtr ((PVOID) VmxRead (GUEST_GDTR_BASE), (ULONG) VmxRead (GUEST_GDTR_LIMIT));

  //MsrWrite (MSR_GS_BASE, VmxRead (GUEST_GS_BASE));
  //MsrWrite (MSR_FS_BASE, VmxRead (GUEST_FS_BASE));

  // FIXME???
  // restore ds, es
  //CmSetDS((USHORT)VmxRead(GUEST_DS_SELECTOR));
  //CmSetES((USHORT)VmxRead(GUEST_ES_SELECTOR));

  // cs and ss must be the same with the guest OS in this implementation

  // restore old IDTR
  CmReloadIdtr ((PVOID) VmxRead (GUEST_IDTR_BASE), (ULONG) VmxRead (GUEST_IDTR_LIMIT));

  return;
}

#ifdef CONFIG_PERF_ENABLE
static VOID NTAPI _perf_print_all(PCPU cpu)
{
	ULONG trap_index;
	/* Hypervisor Statics */
	print("********* Processor %d ***********\n", 
			KeGetCurrentProcessorNumber());
	
	assert((cpu->switch_to_hypervisor_quantity), 
		("_perf_print_all():No trapping to hypervisor occurs?"));
	print("Hypervisor Switches:%I64d, Total Hypervisor Time:%I64d, Average TSC:%I64d\n", 
			cpu->switch_to_hypervisor_quantity,
			cpu->total_hypervisor_time,
			(cpu->total_hypervisor_time / cpu->switch_to_hypervisor_quantity));

	print("EPT Flush Happens:%I64d, Total EPT Flush Time:%I64d, Average TSC:%I64d\n", 
			cpu->ept_flush_quantity,
			cpu->total_eptflush_time,
			(cpu->total_eptflush_time / cpu->ept_flush_quantity));

	/* Guest Statics */
	assert((cpu->switch_to_guest_quantity), ("_perf_print_all():No resuming to guest occurs?"));
	print("Guest Switches:%I64d, Total Guest Time:%I64d, Average TSC:%I64d\n", 
			cpu->switch_to_guest_quantity,
			cpu->total_guest_time,
			(cpu->total_guest_time / cpu->switch_to_guest_quantity));

	/* Trap Statics */
	for( trap_index = 0; trap_index < VMX_EXITS_NUM; trap_index++)
	{
		PNBP_TRAP Trap;
		PLIST_ENTRY TrapList;
		
		TrapList = &cpu->TrapsList[trap_index];
		
		Trap = (PNBP_TRAP) TrapList->Flink;
		while (Trap != (PNBP_TRAP) TrapList) 
		{
			Trap = CONTAINING_RECORD (Trap, NBP_TRAP, le);
			assert((Trap->TrapCallback), ("Illegal Trap Founded"));
			
			print("Trap No:%d, Trap Switches:%I64d, Total Trap Execution Time:%I64d, \
					Average TSC:%I64d. Total Trap Dispatch Time:%I64d, Average TSC:%I64d. \
					Total Trap Dispatch Resuming Time:%I64d, Average TSC:%I64d\n", 
					Trap->TrappedVmExit,
					Trap->trap_quantity,
					Trap->total_execution_time,
					(Trap->trap_quantity!=0)?(Trap->total_execution_time / Trap->trap_quantity):(-1),
					Trap->total_dispatch_time,
					(Trap->trap_quantity!=0)?(Trap->total_dispatch_time / Trap->trap_quantity):(-1),
					Trap->total_dispatch_resume_time,
					(Trap->trap_quantity!=0)?(Trap->total_dispatch_resume_time / Trap->trap_quantity):(-1));

			// Print additional perf result for CR access
			if(trap_index == EXIT_REASON_CR_ACCESS)
			{
				print("Trap No:%d, Total Read Execution Time:%I64d, Switches:%I64d, Average TSC:%I64d. \
						Total Write Execution Time:%I64d, Switches:%I64d, Average TSC:%I64d\n", 
						Trap->TrappedVmExit,
						Trap->total_cr3_read_time,
						Trap->cr3_read_quantity,
						(Trap->total_cr3_read_time / Trap->cr3_read_quantity),
						Trap->total_cr3_write_time,
						Trap->cr3_write_quantity,
						(Trap->total_cr3_write_time / Trap->cr3_write_quantity));
			}
			Trap = (PNBP_TRAP) Trap->le.Flink;
		}
	}	
	
}
#endif

/**
 * Shutdown VM
 */
static NTSTATUS NTAPI VmxShutdown (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  BOOLEAN bSetupTimeBomb
)
{	
	// [TODO] Maybe here is a bug?
	UCHAR Trampoline[0x600];

	#ifdef CONFIG_PERF_ENABLE
	_perf_print_all(Cpu);
	#endif
	
	Print(("VmxShutdown(): CPU#%d\n", Cpu->ProcessorNumber));
	#if DEBUG_LEVEL>2
		VmxDumpVmcs ();
	#endif
	InterlockedDecrement (&g_uSubvertedCPUs);

	// The code should be updated to build an approproate trampoline to exit to any guest mode.
	VmxGenerateTrampolineToGuest (Cpu, GuestRegs, Trampoline, bSetupTimeBomb);

	Print(("VmxShutdown(): Trampoline generated\n"));
	VmxDisable ();
	((VOID (*)()) & Trampoline) ();

	// never returns
	return STATUS_UNSUCCESSFUL;
}

/**
 * #VMEXIT Handler Entry
 */
static VOID VmxHandleInterception (
    PCPU Cpu,
    PGUEST_REGS GuestRegs
)
{ //Finished
    NTSTATUS Status;
    ULONG Exitcode;
    PNBP_TRAP Trap;

    if (!Cpu || !GuestRegs)
        return;

    Exitcode = VmxRead (VM_EXIT_REASON);

//#if DEBUG_LEVEL>1
    //DbgPrintEx(	DPFLTR_IHVDRIVER_ID, 
			//	DPFLTR_ERROR_LEVEL,
			//	"Exitcode %d, GuestRIP:0x%llx\n", Exitcode,VmxRead(GUEST_RIP));
//#endif

    if (Exitcode == EXIT_REASON_CR_ACCESS
        && GuestRegs->eax == VIS_EXIT_FN)
    {
        // to uninstall
        VmxShutdown(Cpu, GuestRegs, FALSE);
    }

    // search for a registered trap for this interception
    Status = TrFindRegisteredTrap (Cpu, GuestRegs, Exitcode, &Trap);
    if (!NT_SUCCESS (Status)) 
    {
        Print(("VmxHandleInterception(): TrFindRegisteredTrap() failed for exitcode 0x%llX\n", Exitcode));
        VmxCrash (Cpu, GuestRegs);
        return;
    }

    // we found a trap handler
    Status = TrExecuteGeneralTrapHandler(
        Cpu, 
        GuestRegs, 
        Trap, 
        arch);
    if (!NT_SUCCESS (Status)) 
    {
        Print(("VmxHandleInterception(): HvmExecuteGeneralTrapHandler() failed with status 0x%08hX\n", Status));
    }

	//if(arch->p2m.can_remap)
		//mm_hide_vis_pages(arch);
	//need flush P2M?
	if(arch->p2m.p2m_tlb_flush && arch->p2m.need_flush)
	{
		#ifdef CONFIG_PERF_ENABLE
		Cpu->ept_flush_quantity++;
		Cpu->last_eptflush_start_tsc = perf_start_timer();
		#endif
		
		arch->p2m.p2m_tlb_flush();

		#ifdef CONFIG_PERF_ENABLE
		Cpu->last_eptflush_time = perf_get_execution_time(Cpu->last_eptflush_start_tsc);
		Cpu->total_eptflush_time += Cpu->last_eptflush_time;
		#endif
		
		arch->p2m.p2m_vpid_flush();
		arch->p2m.need_flush = FALSE;
	}

	#ifdef CONFIG_PERF_ENABLE

	Trap->total_dispatch_resume_time += perf_get_execution_time(Trap->dispatch_resume_start_tsc);
	#endif
}

/**
 * Adjust Rip
 */
static VOID NTAPI VmxAdjustRip (
    PCPU Cpu,
    PGUEST_REGS GuestRegs,
    ULONG Delta
)
{
    VmxWrite (GUEST_RIP, VmxRead (GUEST_RIP) + Delta);
    return;
}
