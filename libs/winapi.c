/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file for supporting multi-OS in the future.
* 
*****************************/

#include <libs/winapi.h>
#include <vis/types.h>

VOID win_memcpy(PVOID dest, PVOID src, ULONG offset)
{
	int i = 0;
	PULONG32 pdest = (PULONG32)((ULONG32)dest + offset / BYTES_PER_LONG);
	PULONG32 psrc = (PULONG32)src;
		
	for(i = 0; i < (PAGE_SIZE) / BYTES_PER_LONG; i++)
		pdest[i] = psrc[i];
}

LIST_ENTRY* DDKExInterlockedRemoveHeadList(LIST_ENTRY* list, spinlock_t* lock)
{
	LIST_ENTRY* result = NULL;
	LIST_ENTRY* next_element;

	spin_lock_acquire(lock);
	result = list->Flink;
	next_element = result->Flink;

	if(result == list)
	{
		spin_lock_release(lock);
		return NULL;
	}
	
	list->Flink = next_element;
	next_element->Blink = list;
	spin_lock_release(lock);
	
	return result;
	
}

VOID DDKExInterlockedInsertTailList(LIST_ENTRY* list, LIST_ENTRY* entry, spinlock_t* lock)
{
	LIST_ENTRY* last_ele;

	spin_lock_acquire(lock);
	last_ele = list->Blink;
	last_ele->Flink = entry;
	entry->Blink = last_ele;
	entry->Flink = list;
	list->Blink = entry;
	spin_lock_release(lock);
}

