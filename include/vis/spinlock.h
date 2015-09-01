/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#pragma once
#include <ntddk.h>

#define NO_HOLDER	~0;
typedef ULONG spinlock_t;

extern VOID NTAPI spin_lock_init (
  spinlock_t* plock
);

extern VOID NTAPI spin_lock_acquire (
  spinlock_t* plock
);

extern VOID NTAPI spin_lock_release (
  spinlock_t* plock
);
