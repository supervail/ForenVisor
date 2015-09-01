/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#pragma once

#include <vis/config.h>

#define TRUE    1
#define FALSE   0
#undef NULL
	#define NULL 0
	
#define BITS_PER_BYTE 8
#define u32_to_u64(high, low)	(((ULONG64)((high)))<< 32 | (low))
#define u64high_to_u32(val) 	((ULONG32)(val >> 32))
#define u64low_to_u32(val) 		((ULONG32)val)

#if defined(_X86_)
        #define BITS_PER_LONG 32
        #define BYTES_PER_LONG 4
        #define LONG_BYTEORDER 2
#elif defined(_X64_)
        #define BITS_PER_LONG 64
        #define BYTES_PER_LONG 8
        #define LONG_BYTEORDER 3
#endif

typedef UCHAR  bool_t;

/* Types for Memory management. */
/* The following types is 64 bits long on X64 platform, while 32 bits long on X86 platform */
typedef ULONG mfn_t;
typedef ULONG gfn_t;
typedef ULONG gvfn_t;

typedef ULONG gpaddr_t;
typedef ULONG gvaddr_t;
typedef ULONG mpaddr_t;

/* Types for IO interception */
typedef signed char		i8;
typedef signed short int	i16;
typedef signed int		i32;
typedef signed long long int	i64;
typedef unsigned char		u8;
typedef unsigned short int	u16;
typedef unsigned int		u32;
typedef unsigned long long int	u64;
