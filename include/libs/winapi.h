/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file for supporting multi-OS in the future.
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/spinlock.h>

VOID win_memcpy(PVOID dest, PVOID src, ULONG offset);
LIST_ENTRY* DDKExInterlockedRemoveHeadList(LIST_ENTRY* list, spinlock_t* lock);
VOID DDKExInterlockedInsertTailList(LIST_ENTRY* list, LIST_ENTRY* entry, spinlock_t* lock);

