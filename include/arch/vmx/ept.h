/****************************
* 2011.1     Miao Yu     Implement EPT for Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#pragma once
#include <vis/types.h>
#include <vis/mm.h>

#define EPT_DEFAULT_MT      	6
#define EPT_DEFAULT_GAW     	3
#define EPT_TABLE_ORDER     	9

#define EPT_EACHTABLE_ENTRIES 	512
// The <ept_entry_t> declaration is stolen from Xen 4. Shame...

/* EPT violation qualifications definitions */
#define _EPT_READ_VIOLATION         0
#define EPT_READ_VIOLATION          (1UL<<_EPT_READ_VIOLATION)
#define _EPT_WRITE_VIOLATION        1
#define EPT_WRITE_VIOLATION         (1UL<<_EPT_WRITE_VIOLATION)
#define _EPT_EXEC_VIOLATION         2
#define EPT_EXEC_VIOLATION          (1UL<<_EPT_EXEC_VIOLATION)
#define _EPT_EFFECTIVE_READ         3
#define EPT_EFFECTIVE_READ          (1UL<<_EPT_EFFECTIVE_READ)
#define _EPT_EFFECTIVE_WRITE        4
#define EPT_EFFECTIVE_WRITE         (1UL<<_EPT_EFFECTIVE_WRITE)
#define _EPT_EFFECTIVE_EXEC         5
#define EPT_EFFECTIVE_EXEC          (1UL<<_EPT_EFFECTIVE_EXEC)
#define _EPT_GAW_VIOLATION          6
#define EPT_GAW_VIOLATION           (1UL<<_EPT_GAW_VIOLATION)
#define _EPT_GLA_VALID              7
#define EPT_GLA_VALID               (1UL<<_EPT_GLA_VALID)
#define _EPT_GLA_FAULT              8
#define EPT_GLA_FAULT               (1UL<<_EPT_GLA_FAULT)

typedef union {
    struct {
        ULONG64 r       :   1,
        w           :   1,
        x           :   1,
        emt         :   3, /* EPT Memory type */
        ipat        :   1, /* Ignore PAT memory type */
        sp_avail    :   1, /* Is this a superpage? */
        avail1      :   4,
        mfn         :   40,
        avail2      :   12;
    };
    ULONG64 epte;
} ept_entry_t;

typedef union{
    struct {
        ULONG64 etmt :3,
        gaw  :3,
        rsvd :6,
        asr  :52;
    };
    ULONG64 eptp;
}ept_control;

VOID NTAPI ept_init(struct arch_phy* arch);

