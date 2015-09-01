/****************************
* 2011.1     Miao Yu     Implement a simple Bitset container as the utility for Vis's case study.
* 
*****************************/

#include <libs/bitset.h>
#include <vis/spinlock.h>
#include <vis/mm.h>

PUCHAR container;
static ULONG num_elements;
static ULONG least_clr_byte_idx;
static spinlock_t bitset_lock;

VOID NTAPI bitset_init(ULONG in_num_elements)
{
	ULONG size = in_num_elements / BITS_PER_BYTE + 1;

	num_elements = in_num_elements;
	//container = (PUCHAR) MmAllocatePages(BYTES_TO_PAGES(size), 0, TRUE);
	container = (PUCHAR) ExAllocatePoolWithTag (NonPagedPool, 
		BYTES_TO_PAGES(size) * PAGE_SIZE, ITL_TAG);
	memset(container, 0, size);

	spin_lock_init(&bitset_lock);
	least_clr_byte_idx = 0;
	
}

VOID NTAPI bitset_finalize(void)
{
	ULONG size = num_elements / BITS_PER_BYTE + 1;
	
	memset(container, 0, size);
}

BOOLEAN NTAPI bitset_isset(ULONG pos)
{
	ULONG byte_index, inner_index;

	assert((pos < num_elements), ("bitset_isset: out of bound, <pos>:%d", pos));

	spin_lock_acquire(&bitset_lock);
	byte_index = pos / BITS_PER_BYTE;
	inner_index = pos % BITS_PER_BYTE;
	spin_lock_release(&bitset_lock);
	
	return (container[byte_index] & (1 << inner_index));

	
}
VOID NTAPI bitset_set(ULONG pos)
{
	ULONG byte_index, inner_index;

	assert((pos < num_elements), ("bitset_set: out of bound, <pos>:%d", pos));

	spin_lock_acquire(&bitset_lock);
	byte_index = pos / BITS_PER_BYTE;
	inner_index = pos % BITS_PER_BYTE;

	assert((!(container[byte_index] & (1 << inner_index))), ("Already set?"));
	container[byte_index] = container[byte_index] | (1 << inner_index);

	spin_lock_release(&bitset_lock);
}

VOID NTAPI bitset_clr(ULONG pos)
{
	ULONG byte_index, inner_index;

	assert((pos < num_elements), ("bitset_set: out of bound, <pos>:%d", pos));

	spin_lock_acquire(&bitset_lock);
	byte_index = pos / BITS_PER_BYTE;
	inner_index = pos % BITS_PER_BYTE;

	assert(((container[byte_index] & (1 << inner_index))), ("Already clear?"));
	container[byte_index] = container[byte_index] & (~(1 << inner_index));
	spin_lock_release(&bitset_lock);
}


struct bitset_idx_grp NTAPI bitset_least_clr_idx(PULONG32 avail_num_entries)
{
	struct bitset_idx_grp grp= {0};
	ULONG size, remaining;
	ULONG i, k, j;

	size = num_elements / BITS_PER_BYTE;
	remaining = num_elements % BITS_PER_BYTE;
	j = 0;

	spin_lock_acquire(&bitset_lock);
	for( i = least_clr_byte_idx; i < size; i++)
	{
		if (j >= IDX_GRP_LENGTH) 
			break;
		
		if(container[i] == 0xff)
		{
			least_clr_byte_idx++;
			continue;
		}
		else
		{
			for (k = 0; (k < BITS_PER_BYTE && j < IDX_GRP_LENGTH); k++)
			{
				if  (!(container[i] & (1 << k))) // found a clear bit
				{
					grp.idx[j++] = i * BITS_PER_BYTE + k;
				}
			}
		}
	}

	if (j < IDX_GRP_LENGTH)
	{
		for (k = 0; (k < remaining && j < IDX_GRP_LENGTH); k++)
		{
				if  (!(container[size] & (1 << k))) // found a clear bit
				{
					grp.idx[j++] = i * BITS_PER_BYTE + k;
				}
		}
	}

	*avail_num_entries = j;

	spin_lock_release(&bitset_lock);
	return grp;
}

