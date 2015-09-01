/****************************
* 2011.1     Miao Yu     Implement a simple Bitset container as the utility for Vis's case study.
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/types.h>

#define IDX_GRP_LENGTH (BITS_PER_BYTE)
struct bitset_idx_grp
{
	ULONG idx[IDX_GRP_LENGTH];
};
VOID NTAPI bitset_init(ULONG in_num_elements);

VOID NTAPI bitset_finalize(void);

BOOLEAN NTAPI bitset_isset(ULONG pos);

VOID NTAPI bitset_set(ULONG pos);

VOID NTAPI bitset_clr(ULONG pos);

struct bitset_idx_grp NTAPI bitset_least_clr_idx(PULONG32 avail_num_entries);

