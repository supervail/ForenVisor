/****************************
* 2011.1     Miao Yu     	Implement Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once

// This code is stolen from Xen 4

/* These are the region types. They match the architectural specification. */
#define MTRR_TYPE_UNCACHABLE 0
#define MTRR_TYPE_WRCOMB     1
#define MTRR_TYPE_WRTHROUGH  4
#define MTRR_TYPE_WRPROT     5
#define MTRR_TYPE_WRBACK     6
#define MTRR_NUM_TYPES       7
