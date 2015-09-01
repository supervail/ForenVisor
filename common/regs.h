/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once
#include "common.h"
#include <ntddk.h>

USHORT NTAPI RegGetCs (
);
USHORT NTAPI RegGetDs (
);
USHORT NTAPI RegGetEs (
);
USHORT NTAPI RegGetSs (
);
USHORT NTAPI RegGetFs (
);
USHORT NTAPI RegGetGs (
);

ULONG NTAPI RegGetCr0 (
);
ULONG NTAPI RegGetCr2 (
);
ULONG NTAPI RegGetCr3 (
);
ULONG NTAPI RegGetCr4 (
);
ULONG NTAPI RegGetCr8 (
);
ULONG NTAPI RegGetRflags (
);
ULONG NTAPI RegGetEsp (
);

ULONG NTAPI GetIdtBase (
);
USHORT NTAPI GetIdtLimit (
);
ULONG NTAPI GetGdtBase (
);
USHORT NTAPI GetGdtLimit (
);
USHORT NTAPI GetLdtr (
);

USHORT NTAPI GetTrSelector (
);

ULONG NTAPI RegGetEbx (
);
ULONG NTAPI RegGetEax (
);

ULONG NTAPI RegGetTSC (
);

ULONG NTAPI RegGetDr0 (
);
ULONG NTAPI RegGetDr1 (
);
ULONG NTAPI RegGetDr2 (
);
ULONG NTAPI RegGetDr3 (
);
ULONG NTAPI RegGetDr6 (
);
ULONG NTAPI RegSetDr0 (
);
ULONG NTAPI RegSetDr1 (
);
ULONG NTAPI RegSetDr2 (
);
ULONG NTAPI RegSetDr3 (
);

ULONG NTAPI RegSetCr3 (
  ULONG NewCr3
);
ULONG NTAPI RegSetCr8 (
  ULONG NewCr8
);
