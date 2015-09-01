/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
					Add EPT #PF handling and activate the functions related to the case
					study.
* 
*****************************/

#pragma once

#include <ntddk.h>
#include <vis/vcpu.h>

/**
 * effects: Register traps in this function
 * requires: <Cpu> is valid
 */
NTSTATUS NTAPI VmxRegisterTraps (
    PCPU Cpu,
    struct arch_phy* arch
);
