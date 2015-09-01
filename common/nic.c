#include <vis/io.h>
#include <vis/config.h>
#include <vis/types.h>
#include <vis/arch.h>
#include <vis/mm.h>
#include <libs/bitset.h>
#include <libs/winapi.h>
#include <libs/atom.h>
#include <arch/msr.h>


void read_phymem(u32 addr, ULONG len, PVOID first) {
	PVOID virtAddr;
	PHYSICAL_ADDRESS phyAddr;
	PUCHAR src, dst;
	ULONG i;

	phyAddr.QuadPart = addr;	
	virtAddr = MmMapIoSpace(phyAddr, len, FALSE);
	if (!virtAddr)
		__asm{ int 3 }
	src = (PUCHAR)virtAddr;
	dst = (PUCHAR)first;
	for (i = 0; i < len; i++)
		dst[i] = src[i];
	
	MmUnmapIoSpace(virtAddr, len);
}

void write_phymem(u32 addr, ULONG len, PVOID first) {
	PVOID virtAddr;
	PHYSICAL_ADDRESS phyAddr;
	PUCHAR src, dst;
	ULONG i;

	phyAddr.QuadPart = addr;	
	virtAddr = MmMapIoSpace(phyAddr, len, FALSE);

	dst = (PUCHAR)virtAddr;
	src = (PUCHAR)first;
	for (i = 0; i < len; i++)
		dst[i] = src[i];
	
	MmUnmapIoSpace(virtAddr, len);
}


#ifdef NIC_WRITE_FILE

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos)   \
	 (((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
	 (((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli)  \
	 (((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds)	 \
	 (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define MINUTES(minutes)	 \
	 (((signed __int64)(minutes)) * SECONDS(60L))

#define HOURS(hours)		 \
	 (((signed __int64)(hours)) * MINUTES(60L))
	 

#define THREAD_NUM 1
#define MAX_RETIRE_SLOT_NUM 40

struct nic_task_entry
{
	LIST_ENTRY le;
	ULONG32 cmd;
	gfn_t data_len;
	UCHAR data[NIC_BUF_LEN];
};

static ULONG32 missing_data;

static LIST_ENTRY nic_task_list;
static spinlock_t nic_task_list_lock;

static LIST_ENTRY retire_task_list;
static spinlock_t retire_task_list_lock;

static ULONG32 retire_slot_num = MAX_RETIRE_SLOT_NUM;

static KEVENT shutdown_event;
static PETHREAD task_thread[THREAD_NUM];

static HANDLE handle_tx;
static HANDLE handle_rv;



static VOID NTAPI thread_nic_file_create(ULONG32 cmd)
{
	UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
	NTSTATUS status;
    IO_STATUS_BLOCK    ioStatusBlock;
	PHANDLE phandle;
	
	// Create output file
    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.
    assert((!handle_tx), ("Already open a file handle_tx"));
	assert((PASSIVE_LEVEL ==  KeGetCurrentIrql()), 
		("I/O operations occurs in non-Passive IRQL"));

	switch (cmd){
		case CREATE_FILE_TX:
			RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\vis_nic_tx.bin");
			phandle = &handle_tx;
			break;
		case CREATE_FILE_RV:
			RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\vis_nic_rv.bin");
			phandle = &handle_rv;
			break;
		default:
			RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\vis_nic.bin");
			phandle = NULL;
			break;

	}
    
    InitializeObjectAttributes(&objAttr, &uniName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateFile(phandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, 0, 
							FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 
                            FILE_NON_DIRECTORY_FILE|FILE_RANDOM_ACCESS|FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL, 0);
	
	assert((status == STATUS_SUCCESS), ("I/O error"));

}

static VOID NTAPI thread_nic_file_close(PHANDLE phandle)
{
	UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
	NTSTATUS status;
    IO_STATUS_BLOCK    ioStatusBlock;
	;
	
	// Create output file
    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.
	assert((PASSIVE_LEVEL ==  KeGetCurrentIrql()), 
		("I/O operations occurs in non-Passive IRQL"));
	
    assert((*phandle != NULL), ("Closing invalid file handle_tx!"));
	
	status = ZwClose(*phandle);
	*phandle = NULL;
	
	assert((status == STATUS_SUCCESS), ("I/O error"));
	

}


static VOID NTAPI thread_nic_file_write(ULONG32 cmd, PHANDLE phandle, VOID* content, ULONG content_size)
{
	IO_STATUS_BLOCK    iosBlock;
    NTSTATUS        ntStatus = STATUS_UNSUCCESSFUL;
	ULONG64 written_bytes;
	PULONG64 pulBytesWrite = &written_bytes;
	
	
    if(!*phandle)
    	thread_nic_file_create(cmd);
	
    if(!content || !content_size)
		__asm {int 3}

    // All kernel file operating functions must running on PASSIVE_LEVEL
    assert((PASSIVE_LEVEL ==  KeGetCurrentIrql()), ("I/O operations occurs in non-Passive IRQL"));

    *pulBytesWrite = 0;
	
	ntStatus = ZwWriteFile(*phandle, NULL, NULL, NULL, &iosBlock, content, content_size, NULL, NULL);
	assert((ntStatus == STATUS_SUCCESS), ("I/O First half error"));
	
	// [TODO] Need more operation on *pulBytesWrite
    *pulBytesWrite = (ULONG)iosBlock.Information;

	assert((written_bytes), ("Nothing is written"));
}

NTSTATUS NTAPI nic_file_create(ULONG32 cmd)
{
	struct nic_task_entry *new_entry;

	new_entry = (struct nic_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock);

	if(!new_entry)
		return STATUS_UNSUCCESSFUL;
	
	new_entry->cmd = cmd;

	DDKExInterlockedInsertTailList (&nic_task_list, &new_entry->le, 
		&nic_task_list_lock);

	atom_dec(retire_slot_num);
	return STATUS_SUCCESS;
}

static VOID NTAPI _client_execute_tasks(void)
{
	struct nic_task_entry *task_entry;

  	while (task_entry = 
	  	(struct nic_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&nic_task_list, 
	  		&nic_task_list_lock)) 
  	{

    	task_entry = CONTAINING_RECORD (task_entry, struct nic_task_entry, le);			

    	switch (task_entry->cmd) {
    		case CREATE_FILE_RV:
			case CREATE_FILE_TX:
      			thread_nic_file_create(task_entry->cmd);
      			break;
    		case WRITE_FILE_RV:
      			thread_nic_file_write(task_entry->cmd, &handle_rv, task_entry->data, task_entry->data_len);
      			break;
			case WRITE_FILE_TX:
				thread_nic_file_write(task_entry->cmd, &handle_tx, task_entry->data, task_entry->data_len);
				break;
			case CLOSE_FILE_RV:
				thread_nic_file_close(&handle_rv);
				break;
			case CLOSE_FILE_TX:
				thread_nic_file_close(&handle_tx);
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

static VOID NTAPI nic_thread_init(void)
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

				DbgPrint("NicClient: Failed to start ScanWindowsThread, status 0x%08X\n",Status);
			}

		if (!NT_SUCCESS(Status=ObReferenceObjectByHandle(
								hThread,
								THREAD_ALL_ACCESS,
								NULL,
								KernelMode,
								&task_thread[tid],
								NULL))) {

			DbgPrint("NicClient: Failed to get thread object of the ScanWindowsThread, status 0x%08X\n",Status);
			ZwClose(hThread);
		}

		ZwClose(hThread);
	}
}

VOID NTAPI nic_init(void)
{
	int task_entry_index = 0;
	struct nic_task_entry *new_entry;

	InitializeListHead(&nic_task_list);
	spin_lock_init(&nic_task_list_lock);
	InitializeListHead(&retire_task_list);
	spin_lock_init(&retire_task_list_lock);
	KeInitializeEvent(&shutdown_event,NotificationEvent,FALSE);

	nic_thread_init();

	for(task_entry_index = 0; task_entry_index < (MAX_RETIRE_SLOT_NUM); task_entry_index++) // 0x3800
	{
		new_entry = (struct nic_task_entry *) MmAllocatePages(
			BYTES_TO_PAGES(sizeof(struct nic_task_entry)), 
			NULL, FALSE);

		DDKExInterlockedInsertTailList (&retire_task_list, &new_entry->le, 
			&retire_task_list_lock);
	}

	retire_slot_num = MAX_RETIRE_SLOT_NUM;
}


NTSTATUS NTAPI nic_file_write(ULONG32 cmd, VOID *content, ULONG content_size)
{
	struct nic_task_entry *new_entry;
		
	new_entry = (struct nic_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock);

	if(!new_entry)
		return STATUS_UNSUCCESSFUL;
	//__asm{int 3}
	win_memcpy(new_entry->data, content, content_size);

	new_entry->cmd = cmd;
	new_entry->data_len = content_size;
	
	DDKExInterlockedInsertTailList (&nic_task_list, &new_entry->le, 
		&nic_task_list_lock);

	atom_dec(retire_slot_num);
	__asm{int 3}
	return STATUS_SUCCESS;
}



static NTSTATUS NTAPI nic_file_close(ULONG32 cmd)
{
	struct nic_task_entry *new_entry;

	new_entry = (struct nic_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock);

	if(!new_entry)
		return STATUS_UNSUCCESSFUL;	
	
	new_entry->cmd = cmd;

	DDKExInterlockedInsertTailList (&nic_task_list, &new_entry->le, 
		&nic_task_list_lock);

	atom_dec(retire_slot_num);
	return STATUS_SUCCESS;
}



VOID NTAPI nic_finish(void)
{
	struct nic_task_entry *task_entry;
	NTSTATUS status;
	
	if (handle_rv)
		nic_file_close(CLOSE_FILE_RV);

	if (handle_tx)
		nic_file_close(CLOSE_FILE_TX);
		
}

VOID NTAPI nic_finalize(void)
{
	struct nic_task_entry *task_entry;
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
	

	while (task_entry = 
	  	(struct nic_task_entry *) DDKExInterlockedRemoveHeadList (
	  		&retire_task_list, 
	  		&retire_task_list_lock)) 
  	{
    	task_entry = CONTAINING_RECORD (task_entry, struct nic_task_entry, le);			

		ExFreePool((PVOID)task_entry);
 	}
}


#endif



