/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#include <vis/config.h>
#include <vis/hvm.h>
#include <vis/mm.h>
#include <vis/traps.h>

#ifdef CONFIG_PERF_ENABLE
#include <vis/perf.h>
#endif
/**
 * effects:Build and Initialize General Trap struct (which is also a Trap struct).
 */
NTSTATUS NTAPI TrInitializeGeneralTrap (
    PCPU Cpu,
    ULONG TrappedVmExit,
    UCHAR RipDelta,
    NBP_TRAP_CALLBACK TrapCallback,
    PNBP_TRAP *pInitializedTrap
)
{//Finish
    PNBP_TRAP Trap;
	Print(("HelloWorld:TrInitializeGeneralTrap():TrappedVmExit 0x%x\n", TrappedVmExit));

    if (!Cpu || 
        !TrapCallback || 
        !Hvm->ArchIsTrapValid (TrappedVmExit) ||//<----------------5.1 Finish
        !pInitializedTrap)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Trap = (PNBP_TRAP)MmAllocatePages (BYTES_TO_PAGES (sizeof (NBP_TRAP)), NULL, TRUE);
    if (!Trap) 
    {
        Print(("HelloWorld:TrInitializeGeneralTrap(): Failed to allocate NBP_TRAP structure (%d bytes)\n", sizeof (NBP_TRAP)));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory (Trap, sizeof (NBP_TRAP));

    Trap->TrapType = TRAP_GENERAL;
    Trap->TrappedVmExit = TrappedVmExit;
    Trap->RipDelta = RipDelta;
    Trap->TrapCallback = TrapCallback;

    *pInitializedTrap = Trap;

    return STATUS_SUCCESS;
}

/**
 * effects: Register trap struct.
 */
NTSTATUS NTAPI TrRegisterTrap (
  PCPU Cpu,
  PNBP_TRAP Trap
)
{
	PLIST_ENTRY TrapList;
	ULONG TrappedVmExit;

	if (!Cpu || !Trap)
		return STATUS_INVALID_PARAMETER;

	TrappedVmExit = Trap->TrappedVmExit;
	//TODO - Solve this bug.
	//BUG:In SVM the exitcode maybe >256 or <0, we don't consider this yet
	TrapList = &Cpu->TrapsList[TrappedVmExit];
	
	InsertTailList (TrapList, &Trap->le);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrExecuteGeneralTrapHandler (
    PCPU Cpu,
    PGUEST_REGS GuestRegs,
    PNBP_TRAP Trap,
    struct arch_phy* arch
)
{	
	BOOLEAN status;
    if (!Cpu || !GuestRegs || !Trap || (Trap->TrapType != TRAP_GENERAL))
        return STATUS_INVALID_PARAMETER;

	#ifdef CONFIG_PERF_ENABLE
	Trap->last_dispatch_time = perf_get_execution_time(Cpu->last_hypervisor_start_tsc);
	Trap->total_dispatch_time += Trap->last_dispatch_time;
	Trap->last_execution_start_tsc = perf_start_timer();
	#endif
	
	status = Trap->TrapCallback (Cpu, GuestRegs, Trap, arch);

	#ifdef CONFIG_PERF_ENABLE
	Trap->last_execution_time= perf_get_execution_time(Trap->last_execution_start_tsc);
	Trap->total_execution_time += Trap->last_execution_time;
	Trap->trap_quantity++;

	if(Trap->cr3_read_write_ctl == CR3_READ_HANDLING)
	{
		Trap->cr3_read_quantity++;
		Trap->total_cr3_read_time += Trap->last_execution_time;
	}
	else if(Trap->cr3_read_write_ctl == CR3_WRITE_HANDLING)
	{
		Trap->cr3_write_quantity++;
		Trap->total_cr3_write_time += Trap->last_execution_time;
	}

	Trap->dispatch_resume_start_tsc = perf_start_timer();
	#endif
	
    if (status) 
    {
        // trap handler wants us to adjust guest's RIP
        Hvm->ArchAdjustRip(Cpu, GuestRegs, Trap->RipDelta);
    }

    return STATUS_SUCCESS;
}
/**
 * Search Registered Traps
 */
NTSTATUS NTAPI TrFindRegisteredTrap (
    PCPU Cpu,
    PGUEST_REGS GuestRegs,
    ULONG exitcode,
    PNBP_TRAP *pTrap
)
{
    PLIST_ENTRY TrapList;
    PNBP_TRAP Trap;
	ULONG32 exit_qualification;
    ULONG32 cr;

	if (!Cpu || !GuestRegs || !pTrap)
		return STATUS_INVALID_PARAMETER;

	TrapList = &Cpu->TrapsList[exitcode];
	
	Trap = (PNBP_TRAP) TrapList->Flink;
	while (Trap != (PNBP_TRAP) TrapList) 
	{
		Trap = CONTAINING_RECORD (Trap, NBP_TRAP, le);
		assert((Trap), ("No trap handler is registered with Exitcode:%d", exitcode));
		if (Trap->TrapCallback) 
		{
			if (Trap->TrapType == TRAP_GENERAL)
			{
				*pTrap = Trap;
				return STATUS_SUCCESS;
			}

		}
		Trap = (PNBP_TRAP) Trap->le.Flink;
	}

	return STATUS_NOT_FOUND;
}
