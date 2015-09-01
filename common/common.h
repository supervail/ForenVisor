/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/


#pragma once

#include <vis/types.h>
#include <vis/config.h>

#define	ENABLE_HYPERCALLS
//#define       SET_PCD_BIT     // Set PCD for BP's pages (Non Cached)

typedef NTSTATUS (
  NTAPI * PCALLBACK_PROC
) (
  PVOID Param
);

VOID NTAPI CmFreePhysPages (
  PVOID BaseAddress,
  ULONG uNoOfPages
);

NTSTATUS NTAPI CmSubvert (
  PVOID
);

NTSTATUS NTAPI CmSlipIntoMatrix (
  PVOID
);

/**
 * effects:Raise the interruption level to dispatch level, then
 * install VM Root hypervisor by call <CallbackProc>
 */
NTSTATUS NTAPI CmDeliverToProcessor (
  CCHAR cProcessorNumber,
  PCALLBACK_PROC CallbackProc,
  PVOID CallbackParam,
  PNTSTATUS pCallbackStatus
);

/**
 * effects:This method is invoked by HvmSwallowBluepill, and its 
 * main job is to store the GuestOS (Windows)'s enviroment, currently 
 * it stores only the data in the registers. Other env data will 
 * be saved in the further steps.
 **/
NTSTATUS NTAPI CmSubvert (
  PVOID
);


