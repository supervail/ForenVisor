/****************************
* 2011.1     Miao Yu     Implement case study for Vis hypervisor. 
* 
*****************************/

#include <vis/config.h>
#include <vis/types.h>
#include <vis/arch.h>
#include <vis/mm.h>
#include <libs/bitset.h>
#include <examples/guest_mem_dump.h>
#include <libs/winapi.h>
#include <libs/atom.h>
#include <arch/msr.h>
#ifdef EXAMPLE_MEM_DUMP
	#if ((OSVERSION_MASK & NTDDI_VERSION) == NTDDI_WINXP)  /* Windows XP  */
	#pragma WARNING (Mem Dump example will miss dumping some pages on WINXP. Requires Vista or higher OS version)
	#endif

	#ifdef EXAMPLE_MEM_DUMP_PERF
	ULONG64 total_tsc_wincpy = 0;
	ULONG64 total_times_wincpy = 0;
	ULONG64 last_tsc_wincpy = 0;

	ULONG64 total_tsc_remap = 0;
	ULONG64 total_times_remap = 0;
	ULONG64 last_tsc_remap = 0;
	#endif
#endif

#ifdef EXAMPLE_MEM_DUMP

#define CREATE_FILE 1
#define WRITE_FILE 	2
#define CLOSE_FILE 	3

#define THREAD_NUM 1
#define PAGES_PER_DUMP	8 //This field indicate How many pages are dumped during each trap. Must be 8*2^n
#if ((OSVERSION_MASK & NTDDI_VERSION) == NTDDI_WINXP)  /* Windows XP  */
#define MAX_RETIRE_SLOT_NUM (0x2000 / ((PAGES_PER_DUMP+1) / 2))
#else
#define MAX_RETIRE_SLOT_NUM	(0x1000*20 / ((PAGES_PER_DUMP+1) / 2))
#endif
#define RETIRE_SLOT_QUOTA	(0x1000*16 / ((PAGES_PER_DUMP+1) / 2))
struct dump_task_entry
{
	LIST_ENTRY le;
	ULONG32 cmd;
	gfn_t start_gfn;
	gfn_t num_gfn;
	UCHAR data[PAGE_SIZE * PAGES_PER_DUMP];
};

static BOOLEAN on_dumping = FALSE;
static ULONG32 missing_pfn;

static LIST_ENTRY dump_task_list;
static spinlock_t dump_task_list_lock;

static LIST_ENTRY retire_task_list;
static spinlock_t retire_task_list_lock;

static ULONG32 retire_slot_num = MAX_RETIRE_SLOT_NUM;

static KEVENT shutdown_event;
static PETHREAD task_thread[THREAD_NUM];

static HANDLE handle;
static BOOLEAN dumping_pmem;

static gvaddr_t dummy_page_gvaddr;
static gpaddr_t dummy_page_gpaddr;

ULONG32 range_start_gfn = 0;
ULONG32 range_end_gfn = 0;

ULONG32 missing_pfn = 0;

ULONG64 total_tsc = 0;

#define     PTE_BASE        0xC0000000
#define     PDE_BASE        0xC0300000

#define     GET_PDE_VADDRESS(va) ((((ULONG)(va) >> 22) << 2) + PDE_BASE)
#define     GET_PTE_VADDRESS(va) ((((ULONG)(va) >> 12) << 2) + PTE_BASE)

static ULONG64 rdtsc()
{
	__asm {rdtsc}
}
static void MmInvalidatePage(PVOID _PageVA)
{
	__asm{ invlpg	[_PageVA]}
}

static NTSTATUS CmPatchPTEPhysicalAddress (
    PVOID PageVA,                           // va to be patched
    gpaddr_t NewPhysicalAddress     // new pa
)
{
    ULONG Pte,Pde;
	PULONG pPde;                           // pde's address
    PULONG pPte;                           // pte's address

	pPde = (PULONG)GET_PDE_VADDRESS(PageVA);
    pPte  = (PULONG)GET_PTE_VADDRESS(PageVA);
    
    if (!pPde || !pPte || !PageVA)
        return STATUS_INVALID_PARAMETER;
    
    Pde = *pPde;
    if((Pde & 0x80) != 0) //if this is a large page
	{
		Pde &= 0x1fff;
		Pde |= (NewPhysicalAddress & 0xfffffffffe000);
		*pPde = Pde;
		
    }
    else
    {
    
	    Pte = *pPte;
	    // set new pa
	    Pte &= 0xfff;
	    Pte |= (NewPhysicalAddress & 0xfffff000);
	    *pPte = Pte;
    }
    	
    // flush the tlb cache
    MmInvalidatePage ((PVOID)PageVA);

    return STATUS_SUCCESS;
};

static VOID NTAPI thread_dump_file_create(void)
{
	UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
	NTSTATUS status;
    IO_STATUS_BLOCK    ioStatusBlock;
	//LARGE_INTEGER biggest_offset;
	
	// Create output file
    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.
    assert((!handle), ("Already open a file handle"));
	assert((PASSIVE_LEVEL ==  KeGetCurrentIrql()), 
		("I/O operations occurs in non-Passive IRQL"));
	
    RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\vis_dump.bin");
    InitializeObjectAttributes(&objAttr, &uniName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateFile(&handle, GENERIC_WRITE, &objAttr, &ioStatusBlock, 0, 
							FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 
                            FILE_NON_DIRECTORY_FILE|FILE_RANDOM_ACCESS|FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL, 0);
	
	assert((status == STATUS_SUCCESS), ("I/O error"));

}

static VOID NTAPI thread_dump_file_close(void)
{
	UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
	NTSTATUS status;
    IO_STATUS_BLOCK    ioStatusBlock;
	
	// Create output file
    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.
	assert((PASSIVE_LEVEL ==  KeGetCurrentIrql()), 
		("I/O operations occurs in non-Passive IRQL"));
	
    assert((handle != NULL), ("Closing invalid file handle!"));
	
	status = ZwClose(handle);
	handle = NULL;
	
	assert((status == STATUS_SUCCESS), ("I/O error"));

}


static VOID NTAPI thread_dump_file_write(gfn_t start_gfn, VOID* content, ULONG content_size)
{
	IO_STATUS_BLOCK    iosBlock;
    NTSTATUS        ntStatus = STATUS_UNSUCCESSFUL;
	ULONG64 written_bytes;
	PULONG64 pulBytesWrite = &written_bytes;
    LARGE_INTEGER offset;

    if(!handle)
    	thread_dump_file_create();
	
    if(!(content != NULL && content_size!=0))
		__asm {int 3}

    // All kernel file operating functions must running on PASSIVE_LEVEL
    assert((PASSIVE_LEVEL ==  KeGetCurrentIrql()), ("I/O operations occurs in non-Passive IRQL"));

	offset.QuadPart = ((ULONG32)start_gfn) * PAGE_SIZE;
    *pulBytesWrite = 0;
	
	ntStatus = ZwWriteFile(handle, NULL, NULL, NULL, &iosBlock, content, content_size, &offset, NULL);
	assert((ntStatus == STATUS_SUCCESS), ("I/O First half error"));
	
	// [TODO] Need more operation on *pulBytesWrite
    *pulBytesWrite = (ULONG)iosBlock.Information;

	assert((written_bytes), ("Nothing is written"));
}

static NTSTATUS NTAPI dump_file_create(struct arch_phy* arch)
{
	struct dump_task_entry *new_entry;

	new_entry = (struct dump_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock);

	if(!new_entry)
		return STATUS_UNSUCCESSFUL;
	
	new_entry->cmd = CREATE_FILE;

	DDKExInterlockedInsertTailList (&dump_task_list, &new_entry->le, 
		&dump_task_list_lock);

	atom_dec(retire_slot_num);
	return STATUS_SUCCESS;
}

static VOID NTAPI _client_execute_tasks(void)
{
	struct dump_task_entry *task_entry;

  	while (task_entry = 
	  	(struct dump_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&dump_task_list, 
	  		&dump_task_list_lock)) 
  	{

    	task_entry = CONTAINING_RECORD (task_entry, struct dump_task_entry, le);			

    	switch (task_entry->cmd) {
    		case CREATE_FILE:
      			thread_dump_file_create();
      			break;
    		case WRITE_FILE:
      			thread_dump_file_write(task_entry->start_gfn, task_entry->data, task_entry->num_gfn * PAGE_SIZE);
      			break;
			case CLOSE_FILE:
				thread_dump_file_close();
				break;
    		}

		DDKExInterlockedInsertTailList (&retire_task_list, &task_entry->le, 
			&retire_task_list_lock);

		atom_inc(retire_slot_num);
 	}
}

static VOID NTAPI _task_execution_thread(PVOID Param)
{
	LARGE_INTEGER	Interval;

	Interval.QuadPart=RELATIVE(MILLISECONDS(1));

	while (STATUS_TIMEOUT==KeWaitForSingleObject(
							&shutdown_event,
							Executive,
							KernelMode,
							FALSE,
							&Interval)) {

		_client_execute_tasks();
	}


	DbgPrint("ScanWindowsThread(): Shutting down\n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NTAPI dump_thread_init(void)
{
	NTSTATUS	Status;
	UNICODE_STRING	DeviceLink,DeviceName;
	PDEVICE_OBJECT	pDeviceObject;
	HANDLE	hThread;
	ULONG tid;

	for(tid = 0; tid < THREAD_NUM; tid++)
	{
		if (!NT_SUCCESS(Status=PsCreateSystemThread(&hThread,
								(ACCESS_MASK)0L,
								NULL,
								0,
								NULL,
								_task_execution_thread,
								NULL))) {

				DbgPrint("DumperClient: Failed to start ScanWindowsThread, status 0x%08X\n",Status);
			}

		if (!NT_SUCCESS(Status=ObReferenceObjectByHandle(
								hThread,
								THREAD_ALL_ACCESS,
								NULL,
								KernelMode,
								&task_thread[tid],
								NULL))) {

			DbgPrint("DumperClient: Failed to get thread object of the ScanWindowsThread, status 0x%08X\n",Status);
			ZwClose(hThread);
		}

		ZwClose(hThread);
	}
}

VOID NTAPI dump_init(void)
{
	int task_entry_index = 0;
	struct dump_task_entry *new_entry;

	InitializeListHead(&dump_task_list);
	spin_lock_init(&dump_task_list_lock);
	InitializeListHead(&retire_task_list);
	spin_lock_init(&retire_task_list_lock);
	KeInitializeEvent(&shutdown_event,NotificationEvent,FALSE);

	dump_thread_init();
	
	dummy_page_gvaddr =  MmAllocatePages(1, &dummy_page_gpaddr, FALSE);
	assert((dummy_page_gvaddr), ("Allocate error"));

	for(task_entry_index = 0; task_entry_index < (MAX_RETIRE_SLOT_NUM); task_entry_index++) // 0x3800
	{
		new_entry = (struct dump_task_entry *) MmAllocatePages(
			BYTES_TO_PAGES(sizeof(struct dump_task_entry)), 
			NULL, FALSE);

		DDKExInterlockedInsertTailList (&retire_task_list, &new_entry->le, 
			&retire_task_list_lock);
	}

	retire_slot_num = MAX_RETIRE_SLOT_NUM;
}

static VOID NTAPI dump_phys_mem(struct arch_phy* arch)
{
	ULONG32 pfn_num = arch->mm.mm_highest_gfn + 1;
	
	if (dumping_pmem)
		return;
	
	bitset_init(pfn_num);
	range_start_gfn = 0;
	range_end_gfn = arch->mm.mm_highest_gfn;
	
	dump_file_create(arch);

	arch->p2m.p2m_update_all_mapping(P2M_EXECUTABLE | P2M_READABLE);

	{
		struct dump_task_entry *new_entry;
		gfn_t ignore_gfn;
		
		new_entry = (struct dump_task_entry*)retire_task_list.Flink;
		
		while (new_entry != (struct dump_task_entry*) &retire_task_list) {	
			gvaddr_t ignore_gvaddr;
			gpaddr_t ignore_gpaddr;
			
			new_entry = CONTAINING_RECORD (new_entry, struct dump_task_entry, le);
			assert((new_entry),("invalid <new_entry> in <retire_task_list>"));

			for(ignore_gvaddr = (gvaddr_t)new_entry; 
				ignore_gvaddr < ((gvaddr_t)new_entry + sizeof(struct dump_task_entry));
				ignore_gvaddr+=PAGE_SIZE)
			{	
				#ifdef _X86_
					ignore_gpaddr = MmGetPhysicalAddress((PVOID)ignore_gvaddr).LowPart;
				#elif defined(_X64_)
					ignore_gpaddr = MmGetPhysicalAddress((PVOID)ignore_gvaddr).QuadPart;
				#endif
				ignore_gfn = gpaddr_to_gfn(ignore_gpaddr);
				arch->p2m.p2m_update_mapping(ignore_gfn, ignore_gfn, 
					P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MT);
			}
		    new_entry = (struct dump_task_entry *) new_entry->le.Flink;
		}
	}
	// Set flag
	dumping_pmem = 1;
	total_tsc = rdtsc();
}

static NTSTATUS NTAPI dump_file_write(struct arch_phy* arch, gfn_t dump_gfn, ULONG content_size)
{
	struct dump_task_entry *new_entry;
	PVOID content = (PVOID)dummy_page_gvaddr;
	gfn_t start_gfn = (dump_gfn & ~(PAGES_PER_DUMP-1));
	gfn_t gfn;
	ULONG32 offset = 0;
	ULONG32 num_gfn = 0;
		
	new_entry = (struct dump_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock);

	if(!new_entry)
		return STATUS_UNSUCCESSFUL;

	for(gfn = start_gfn; 
		gfn < (start_gfn + PAGES_PER_DUMP) && gfn <= range_end_gfn; 
		gfn++, num_gfn++)
	{
		gpaddr_t gpa = gfn_to_gpaddr(gfn);

		#ifdef EXAMPLE_MEM_DUMP_PERF
		last_tsc_wincpy = rdtsc();
		#endif
		
		CmPatchPTEPhysicalAddress((PVOID)dummy_page_gvaddr, gpa);
	
		win_memcpy(new_entry->data, content, offset);

		#ifdef EXAMPLE_MEM_DUMP_PERF
		total_tsc_wincpy += (rdtsc() - last_tsc_wincpy);
		total_times_wincpy++;
		#endif


		#ifdef EXAMPLE_MEM_DUMP_PERF
		last_tsc_remap= rdtsc();
		#endif
		
		offset += PAGE_SIZE;
		bitset_set(gfn);
		
		arch->p2m.p2m_update_mapping(gfn, gfn, P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MT);

		#ifdef EXAMPLE_MEM_DUMP_PERF
		total_tsc_remap += (rdtsc() - last_tsc_remap);
		total_times_remap++;
		#endif
	}
	new_entry->cmd = WRITE_FILE;
	new_entry->start_gfn = start_gfn;
	new_entry->num_gfn = num_gfn;
	
	DDKExInterlockedInsertTailList (&dump_task_list, &new_entry->le, 
		&dump_task_list_lock);

	atom_dec(retire_slot_num);

	
		
	return STATUS_SUCCESS;
}

static NTSTATUS NTAPI dump_file_close(void)
{
	struct dump_task_entry *new_entry;

	new_entry = (struct dump_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock);

	if(!new_entry)
		return STATUS_UNSUCCESSFUL;	
	
	new_entry->cmd = CLOSE_FILE;

	DDKExInterlockedInsertTailList (&dump_task_list, &new_entry->le, 
		&dump_task_list_lock);

	atom_dec(retire_slot_num);
	return STATUS_SUCCESS;
}

VOID NTAPI dump_remainings(struct arch_phy* arch, PBOOLEAN done)
{
	PHYSICAL_ADDRESS gpa;
	gfn_t gfn;
	gvaddr_t gvaddr;
	ULONG i;
	ULONG32 avail_num_entries = 0; 
	NTSTATUS status;

	if(!dumping_pmem) 
		return;

	if(retire_slot_num < RETIRE_SLOT_QUOTA)
		return;

	while(bitset_isset(range_start_gfn) == TRUE)
		range_start_gfn += PAGES_PER_DUMP;

	if(range_start_gfn <= range_end_gfn)
	{
		status = dump_file_write(arch, range_start_gfn, PAGE_SIZE);
		if(NT_SUCCESS(status))
			range_start_gfn += PAGES_PER_DUMP;
	}
	else
		*done = TRUE;
		
}

VOID NTAPI dump_finish(void)
{
	struct dump_task_entry *task_entry;
	NTSTATUS status;
	
	if(dumping_pmem)
	{
		ULONG64 end = rdtsc();
		ULONG64 sec;
		ULONG64 unit = 31900000;
		
		status = dump_file_close();
		
		total_tsc = end - total_tsc;
		sec = total_tsc / unit;

		print("Total (Sec*100):%d\n", (sec));
		
		#ifdef EXAMPLE_MEM_DUMP_PERF
		print("Total TSC:wincpy %I64d, Average TSC:wincpy %d\n", 
			(total_tsc_wincpy), (total_tsc_wincpy / total_times_wincpy));

		print("Total TSC:remap %I64d, Average TSC:remap %d\n", 
			 (total_tsc_remap), (total_tsc_remap / total_times_remap));
		#endif
		
		if(NT_SUCCESS(status))
			dumping_pmem = 0;
	}
}

VOID NTAPI dump_finalize(void)
{
	struct dump_task_entry *task_entry;
	ULONG tid;

	KeSetEvent(&shutdown_event, 0, FALSE);

	_client_execute_tasks();

	for(tid = 0 ; tid < THREAD_NUM; tid++)
	{
		if (task_thread[tid]) {
			KeWaitForSingleObject(task_thread[tid],Executive,KernelMode,FALSE,NULL);
			ObDereferenceObject(task_thread[tid]);
			task_thread[tid] = NULL;
		}
	}
	
	if(dummy_page_gvaddr)
	{
		CmPatchPTEPhysicalAddress((PVOID)dummy_page_gvaddr, dummy_page_gpaddr);
		ExFreePool((PVOID)dummy_page_gvaddr);
		dummy_page_gvaddr = NULL;
	}

	while (task_entry = 
	  	(struct dump_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock)) 
  	{
    	task_entry = CONTAINING_RECORD (task_entry, struct dump_task_entry, le);			

		ExFreePool((PVOID)task_entry);
 	}
}


static VOID NTAPI dump_on_guest_write(struct arch_phy* arch, gpaddr_t gpaddr)
{
	gvaddr_t gvaddr;
	gfn_t gfn;
	NTSTATUS status;

	// [TODO] Modify to adapt our own private pagetable later.
	gfn = gpaddr_to_gfn(gpaddr);
	
	status = dump_file_write(arch, gfn, PAGE_SIZE);

	if(!NT_SUCCESS(status))
	{
		missing_pfn++;
	}
	
}

BOOLEAN NTAPI ept_handle_violation_ext (struct arch_phy* arch, PHYSICAL_ADDRESS gpa)
{
	gpaddr_t gpaddr;
	gfn_t gfn;
	
	#if defined(_X86_)
		gpaddr = gpa.LowPart;
	#elif defined(_X64_)
		gpaddr = gpa.QuadPart;
	#endif

	dump_on_guest_write(arch, gpaddr);

	// [Superymk] !!!!!!!!!!!!!!!!Here is a bug, we can't handle the condition when the
	//  pending pages exceeds the limit of dump_list's length.
	gfn = gpaddr_to_gfn(gpaddr);
	arch->p2m.p2m_update_mapping(gfn, gfn, P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MT);
	return TRUE;
}

VOID NTAPI VmxDispatchCrAccess_ext (struct arch_phy* arch)
{
	BOOLEAN dump_done = FALSE;
				
	if(on_dumping)
	{  		
		dump_remainings(arch, &dump_done);
		if(dump_done)
		{
			on_dumping = FALSE;
			dump_finish();
		}
	}
}

BOOLEAN NTAPI VmxDispatchCpuid_ext (PGUEST_REGS GuestRegs, struct arch_phy* arch, ULONG fn)
{
	if(fn == START_MEM_DUMP)
	{
		on_dumping = TRUE;
		dump_phys_mem(arch);
		
		return TRUE;
	}
	else if(fn == QUERY_MEM_DUMP)
	{
		GuestRegs->eax = missing_pfn;
		GuestRegs->ebx = 0;
		GuestRegs->ecx = 0;
		GuestRegs->edx = 0;
	
		return TRUE;
	}
	return FALSE;
}
#endif

