/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
* 
*****************************/

#pragma once
#include <vis/config.h>
#include <arch/vmx/vmcs.h>
#include <arch/vmx/vmx.h>

#define PROCESSOR_BOOT 0
#define is_boot_processor(Cpu) (!!(Cpu->ProcessorNumber==PROCESSOR_BOOT))

typedef struct _GUEST_REGS
{
  ULONG32 eax;                  // 0x00         // NOT VALID FOR SVM
  ULONG32 ecx;
  ULONG32 edx;                  // 0x08
  ULONG32 ebx;
  ULONG32 esp;                  // esp is not stored here on SVM
  ULONG32 ebp;
  ULONG32 esi;
  ULONG32 edi;
  ULONG32 eflags;
  
} GUEST_REGS,
 *PGUEST_REGS;

/* 
* Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
* segment descriptor. 
*/
typedef union
{
        USHORT UCHARs;
        struct
        {
                USHORT type:4;              /* 0;  Bit 40-43 */
                USHORT s:1;                 /* 4;  Bit 44 */
                USHORT dpl:2;               /* 5;  Bit 45-46 */
                USHORT p:1;                 /* 7;  Bit 47 */
                // gap!       
                USHORT avl:1;               /* 8;  Bit 52 */
                USHORT l:1;                 /* 9;  Bit 53 */
                USHORT db:1;                /* 10; Bit 54 */
                USHORT g:1;                 /* 11; Bit 55 */
                USHORT Gap:4;
          } fields;
} SEGMENT_ATTRIBUTES;

typedef struct
{
        USHORT sel;
        SEGMENT_ATTRIBUTES attributes;
        ULONG32 limit;
        ULONG64 base;
} SEGMENT_SELECTOR;

typedef struct
{
        USHORT limit0;
        USHORT base0;
        UCHAR base1;
        UCHAR attr0;
        UCHAR limit1attr1;
        UCHAR base2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _CPU *PCPU;
typedef struct _CPU
{

        PCPU SelfPointer;             // MUST go first in the structure; refer to interrupt handlers for details

        VMX Vmx;
		
        ULONG ProcessorNumber;

        //LIST_ENTRY GeneralTrapsList[VMX_EXITS_NUM];  // list of BP_TRAP structures
        //LIST_ENTRY MsrTrapsList;      //
        // LIST_ENTRY IoTrapsList;       //
		LIST_ENTRY TrapsList[VMX_EXITS_NUM];
		
        // PVOID SparePage;              // a single page which was allocated just to get an unused PTE.
        // PHYSICAL_ADDRESS SparePagePA; // original PA of the SparePage
        // PULONG SparePagePTE;

        PSEGMENT_DESCRIPTOR GdtArea;
        gvaddr_t IdtArea;

        gvaddr_t HostStack;              // note that CPU structure reside in this memory region

        // ULONG64 ComPrintLastTsc;

		#ifdef CONFIG_PERF_ENABLE
		ULONG64 last_hypervisor_start_tsc;
		ULONG64 last_guest_start_tsc;
		ULONG64 total_hypervisor_time;
		ULONG64 total_guest_time;
		ULONG64 switch_to_hypervisor_quantity;
		ULONG64 switch_to_guest_quantity;

		//For EPT TLB
		ULONG64 last_eptflush_start_tsc;
		ULONG64 last_eptflush_time;
		ULONG64 total_eptflush_time;
		ULONG64 ept_flush_quantity;

		//For #VMRESUME
		UCHAR ctl_measure_vmresume;
		#endif

		ULONG64 guest_current_tsc;
} CPU;

extern NTSTATUS NTAPI CmInitializeSegmentSelector (
    SEGMENT_SELECTOR *pSegmentSelector,
    USHORT Selector,
    PUCHAR GdtBase
);