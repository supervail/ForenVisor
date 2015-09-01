/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#pragma once
#include <ntddk.h>
#include <vis/print_infos.h>

#define DEBUG			0
#define PRINT_LEVEL		PRINT_WARNING

// Vis Configurations - Stealthy
//#define CONFIG_RESTORE_GUEST_TSC 1
//#define CONFIG_USE_PRIVATE_PAGETABLE 1
#define CONFIG_P2M_HIDE_CODE_DATA 1

// Vis Configurations - Perf Instrumentation
//#define CONFIG_PERF_ENABLE 1

// Examples
//[TODO] Need better design for examples
//#define EXAMPLE_MEM_DUMP 1
#ifdef EXAMPLE_MEM_DUMP
	#define EXAMPLE_MEM_DUMP_PERF 1

	#ifdef CONFIG_USE_PRIVATE_PAGETABLE
		#undef CONFIG_USE_PRIVATE_PAGETABLE
	#endif
#endif

// Vis Configurations - Nic output to file
#define NIC_WRITE_FILE 0

#define PRINT_NOTHING	0
#define PRINT_ERROR		1
#define PRINT_WARNING	2
#define PRINT_INFO		3
#define PRINT_ALL		4

// Compiler Directives
#define STR(x)          #x
#define STR2(x)         STR(x)
#define WARNING(text)   message (__FILE__ "(" STR2(__LINE__) ") :  " #text)
#define noteMacro(text) message (__FILE__ "(" STR2(__LINE__) ") : " STR2(text))

//Print-to-console related functions
#define print(fmt, ...) \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, (PUCHAR) fmt, __VA_ARGS__)

#if (DEBUG > 0)
//[TODO] Obsoleted. Print(x) will be merged into print(x)
#define Print(x) WriteDbgInfo x 
#define dprint(lvl, msg) do{ if( lvl <= PRINT_LEVEL) {\
	DbgPrint("[%s:%d] Debug: ",__FILE__,__LINE__); \
	DbgPrint msg; \
	DbgPrint("\n"); \
	}}while(0)

#define assert(rsn, msg) do { if(!rsn) {	\
	DbgPrint("[%s:%d] Panic: ",__FILE__,__LINE__); \
	DbgPrint msg; \
	_asm{ud2}; }} while(0) 
#define panic(msg) assert(0, msg) 
#else
//[TODO] Obsoleted. Print(x) will be merged into print(x)
#define Print(x) {}
#define dprint(lvl, msg) {}
#define assert(rsn, msg) {}
#define panic(msg) {}
#endif

