/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#pragma once

#include <ntddk.h>
#include <vis/snprintf.h>
#include <vis/spinlock.h>

#define NUM_DEBUG_PAGES 20
#define DEBUG_WINDOW_TAG 'DBG'

extern PVOID g_debugWindowAddrVA;

/**
 * Effects: Write info with format.
 **/
NTSTATUS NTAPI WriteDbgInfo (PUCHAR fmt,...);

/**
 * Effects: Initialize SpinLock, must be called before invoke WriteDbgInfo function
 **/
void NTAPI WriteInfoInit();

void NTAPI WriteInfoDispose();

/**************Private Functions**************/

static NTSTATUS _CreateDebugWindow(ULONG32 numContinuousPages);

static VOID _AppendStringToAddress(PUCHAR str,ULONG32 strLength);

/**
 * Effects: Append the string <str> into the end of the debug window
 * If the debug window not exists, then it will be created at first.
 **/
static NTSTATUS NTAPI _WriteInfo(PUCHAR str,ULONG32 strLength);