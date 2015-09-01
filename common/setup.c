/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#include "setup.h"
#include <vis/hvm.h>
#include <vis/config.h>
#include <vis/p2m.h>
#include <vis/arch.h>
#include <vis/ppt.h>

#ifdef CONFIG_PERF_ENABLE
#include <vis/perf.h>
#endif

#ifdef EXAMPLE_MEM_DUMP
#include <examples/guest_mem_dump.h>
#endif

#ifdef NIC_WRITE_FILE
#include <vis/Io.h>
#endif

static struct arch_phy arch = {0};

NTSTATUS DriverUnload (
    PDRIVER_OBJECT DriverObject
)
{
    //FIXME: do not turn SVM/VMX when it has been turned on by the guest in the meantime (e.g. VPC, VMWare)
    NTSTATUS Status;

	#ifdef EXAMPLE_MEM_DUMP
	dump_finish();
	dump_finalize();
	#endif

	#ifdef NIC_WRITE_FILE
	nic_finish();
	nic_finalize();
	#endif
	
    if (!NT_SUCCESS (Status = HvmSpitOutBluepill ())) 
    {
        Print(("Vis: HvmSpitOutBluepill() failed with status 0x%08hX\n",Status));
        return Status;
    }

	mm_finalize();
	WriteInfoDispose();
	
    return STATUS_SUCCESS;
}


NTSTATUS DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status;
    //__asm{int 3}
	
	WriteInfoInit();

	#ifdef CONFIG_PERF_ENABLE
	perf_init(&arch);
	#endif

	arch_init(&arch);
	
	mm_init(&arch, DriverObject);

	#ifdef EXAMPLE_MEM_DUMP
	// [Superymk] In order to play with mem dump, you need to disable large page in WinXP
	// by setting:HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\LargePageMinimum 
	// to be 0xffffffff
	dump_init();
	#endif


	#ifdef NIC_WRITE_FILE
	nic_init();
	#endif
	
    if (!NT_SUCCESS (Status = hvm_init (&arch))) 
    {
            Print(("Vis: HvmInit() failed with status 0x%08hX\n", Status));
            WriteInfoDispose();
            return Status;
    }
	
	p2m_init(&arch);
	//[TODO] Do not try to use Mm_xx functions before this point at current, otherwise it will not be concealed.
	// Need optimisation for this

	#ifdef CONFIG_USE_PRIVATE_PAGETABLE
	ppt_init(&arch);
	#endif
	
    if (!NT_SUCCESS (Status = HvmSwallowBluepill ())) 
    {
            Print(("HELLOWORLD: HvmSwallowBluepill() failed with status 0x%08hX\n", Status));
            WriteInfoDispose();
            return Status;
    }

    DriverObject->DriverUnload = DriverUnload;
    Print(("Vis: Initialization finished\n"));
	#if DEBUG_LEVEL>1
		Print(("HELLOWORLD: EFLAGS = %#x\n", RegGetRflags ()));
	#endif
	
	//mm_trig_hiding_viscode(DriverObject);
	//arch.p2m.can_remap = TRUE;
    return STATUS_SUCCESS;

}
