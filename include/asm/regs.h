/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once

#include <vis/types.h>

extern USHORT NTAPI RegGetCs (
);
extern USHORT NTAPI RegGetDs (
);
extern USHORT NTAPI RegGetEs (
);
extern USHORT NTAPI RegGetSs (
);
extern USHORT NTAPI RegGetFs (
);
extern USHORT NTAPI RegGetGs (
);

extern ULONG NTAPI RegGetCr0 (
);
extern ULONG NTAPI RegGetCr2 (
);
extern ULONG NTAPI RegGetCr3 (
);
extern ULONG NTAPI RegGetCr4 (
);
extern ULONG NTAPI RegGetCr8 (
);
extern ULONG NTAPI RegSetCr3 (
  ULONG NewCr3
);
extern ULONG NTAPI RegSetCr8 (
  ULONG NewCr8
);
extern ULONG NTAPI RegGetRflags (
);
extern ULONG NTAPI RegGetEsp (
);

extern ULONG NTAPI GetIdtBase (
);
extern USHORT NTAPI GetIdtLimit (
);
extern ULONG NTAPI GetGdtBase (
);
extern USHORT NTAPI GetGdtLimit (
);
extern USHORT NTAPI GetLdtr (
);

extern USHORT NTAPI GetTrSelector (
);

extern ULONG NTAPI RegGetEbx (
);
extern ULONG NTAPI RegGetEax (
);

extern ULONG NTAPI RegGetTSC (
);

extern ULONG NTAPI RegGetDr0 (
);
extern ULONG NTAPI RegGetDr1 (
);
extern ULONG NTAPI RegGetDr2 (
);
extern ULONG NTAPI RegGetDr3 (
);
extern ULONG NTAPI RegGetDr6 (
);
extern NTAPI RegSetDr0 (
        ULONG value
);
extern NTAPI RegSetDr1 (
        ULONG value
);
extern NTAPI RegSetDr2 (
        ULONG value
);
extern NTAPI RegSetDr3 (
        ULONG value
);

