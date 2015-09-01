/****************************
* 2008.3     ITL		Implement  NewBluePill Project on x86_64  
* 2011.1     Miao Yu     	Reorganize it for Vis hypervisor on x86 and x86_64(not finished).
					Add EPT #PF handling and activate the functions related to the case
					study.
* 
*****************************/

#include <vis/config.h>
#include <vis/traps.h>
#include <vis/arch.h>
#include <asm/cpuid.h>
#include <arch/msr.h>
#include <arch/vmx/vmx.h>
#include <arch/vmx/ept.h>
#include <vis/io.h>
#include <vis/pci.h>
#include "vmxtraps.h"
#include "vmx.h"

#ifdef CONFIG_PERF_ENABLE
#include <vis/perf.h>
#endif

#ifdef EXAMPLE_MEM_DUMP
#include <examples/guest_mem_dump.h>
#endif

#ifdef CONFIG_P2M_HIDE_CODE_DATA
static bool_t vis_concealed = FALSE;
#endif

static BOOLEAN NTAPI VmxDispatchIO (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

static BOOLEAN NTAPI VmxDispatchCpuid (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

static BOOLEAN NTAPI VmxDispatchVmxInstrDummy (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

static BOOLEAN NTAPI ept_handle_violation (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

static BOOLEAN NTAPI ept_handle_misconfiguration (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

static BOOLEAN NTAPI VmxDispatchINVD (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

extern BOOLEAN NTAPI VmxDispatchMsrRead (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

extern BOOLEAN NTAPI VmxDispatchMsrWrite (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

static BOOLEAN NTAPI VmxDispatchCrAccess (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
);

/**
 * effects: Register traps in this function
 * requires: <Cpu> is valid
 */
NTSTATUS NTAPI VmxRegisterTraps (
  PCPU Cpu,
  struct arch_phy* arch
)
{//Finished
  	NTSTATUS Status;
  	PNBP_TRAP Trap;

  	// used to set dummy handler for all VMX intercepts when we compile without nested support
  	ULONG32 i, TableOfVmxExits[] = {
    	EXIT_REASON_VMCALL,
    	EXIT_REASON_VMCLEAR,
	    EXIT_REASON_VMLAUNCH,
	    EXIT_REASON_VMRESUME,
	    EXIT_REASON_VMPTRLD,
	    EXIT_REASON_VMPTRST,
	    EXIT_REASON_VMREAD,
	    EXIT_REASON_VMWRITE,
	    EXIT_REASON_VMXON,
	    EXIT_REASON_VMXOFF
	};
    Status = TrInitializeGeneralTrap ( //<----------------4.1 Finish
        Cpu, 
        EXIT_REASON_CPUID, 
        0, // length of the instruction, 0 means length need to be get from vmcs later. 
        VmxDispatchCpuid, //<----------------4.2 Finish
        &Trap);
	if (!NT_SUCCESS (Status)) 
	{
	  	Print(("VmxRegisterTraps(): Failed to register VmxDispatchCpuid with status 0x%08hX\n", Status));
	    return Status;
	}
  	TrRegisterTrap (Cpu, Trap);//<----------------4.3//Finish

    Status = TrInitializeGeneralTrap (
        Cpu, 
        EXIT_REASON_MSR_READ, 
        0, // length of the instruction, 0 means length need to be get from vmcs later. 
        VmxDispatchMsrRead, 
		//VmxDispatchVmxInstrDummy,
        &Trap);
  	if (!NT_SUCCESS (Status)) 
	{
	    Print(("VmxRegisterTraps(): Failed to register VmxDispatchMsrRead with status 0x%08hX\n", Status));
	    return Status;
	}
  	TrRegisterTrap (Cpu, Trap);

	Status = TrInitializeGeneralTrap (
        Cpu, 
        EXIT_REASON_EPT_VIOLATION, 
        0, // length of the instruction, 0 means length need to be get from vmcs later. 
        ept_handle_violation, 
		//VmxDispatchVmxInstrDummy,
        &Trap);
  	if (!NT_SUCCESS (Status)) 
	{
	    Print(("VmxRegisterTraps(): Failed to register VmxDispatchMsrRead with status 0x%08hX\n", Status));
	    return Status;
	}
  	TrRegisterTrap (Cpu, Trap);

	Status = TrInitializeGeneralTrap (
        Cpu, 
        EXIT_REASON_EPT_MISCONFIG, 
        0, // length of the instruction, 0 means length need to be get from vmcs later. 
        ept_handle_misconfiguration, 
		//VmxDispatchVmxInstrDummy,
        &Trap);
  	if (!NT_SUCCESS (Status)) 
	{
	    Print(("VmxRegisterTraps(): Failed to register VmxDispatchMsrRead with status 0x%08hX\n", Status));
	    return Status;
	}
  	TrRegisterTrap (Cpu, Trap);

	Status = TrInitializeGeneralTrap (
	    Cpu, 
	    EXIT_REASON_MSR_WRITE, 
	    0,   // length of the instruction, 0 means length need to be get from vmcs later. 
	    VmxDispatchMsrWrite, 
	 	//VmxDispatchVmxInstrDummy,
	    &Trap);
	if (!NT_SUCCESS (Status)) 
	{
	    Print(("VmxRegisterTraps(): Failed to register VmxDispatchMsrWrite with status 0x%08hX\n", Status));
	    return Status;
	}
	TrRegisterTrap (Cpu, Trap);

  Status = TrInitializeGeneralTrap (
      Cpu, 
      EXIT_REASON_CR_ACCESS, 
      0,  // length of the instruction, 0 means length need to be get from vmcs later. 
      VmxDispatchCrAccess, 
      &Trap);
  if (!NT_SUCCESS (Status)) 
  {
    Print(("VmxRegisterTraps(): Failed to register VmxDispatchCrAccess with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  Status = TrInitializeGeneralTrap (
      Cpu, 
      EXIT_REASON_INVD, 
      0,  // length of the instruction, 0 means length need to be get from vmcs later. 
      VmxDispatchINVD, 
      &Trap);
  if (!NT_SUCCESS (Status)) 
  {
    Print(("VmxRegisterTraps(): Failed to register VmxDispatchINVD with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  Status = TrInitializeGeneralTrap (
      Cpu, 
      EXIT_REASON_EXCEPTION_NMI, 
      0,  // length of the instruction, 0 means length need to be get from vmcs later. 
      VmxDispatchVmxInstrDummy,//VmxDispatchPageFault, 
      &Trap);
  if (!NT_SUCCESS (Status)) 
  {
    Print(("VmxRegisterTraps(): Failed to register VmxDispatchPageFault with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  // set IO handler
  Status = TrInitializeGeneralTrap (
      Cpu, 
      EXIT_REASON_IO_INSTRUCTION, 
      0,  // length of the instruction, 0 means length need to be get from vmcs later. 
      VmxDispatchIO,
      &Trap);
  if (!NT_SUCCESS (Status)) 
  {
    Print(("VmxRegisterTraps(): Failed to register VmxDispatchIO with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  // set dummy handler for all VMX intercepts if we compile without nested support
  for (i = 0; i < sizeof (TableOfVmxExits) / sizeof (ULONG32); i++) 
  {
      Status = TrInitializeGeneralTrap (
          Cpu, 
          TableOfVmxExits[i], 
          0,    // length of the instruction, 0 means length need to be get from vmcs later. 
          VmxDispatchVmxInstrDummy, 
          &Trap);
    if (!NT_SUCCESS (Status)) 
    {
      Print(("VmxRegisterTraps(): Failed to register VmxDispatchVmon with status 0x%08hX\n", Status));
      return Status;
    }
    TrRegisterTrap (Cpu, Trap);
  }

  return STATUS_SUCCESS;
}


u8 nicbuf_rv[NIC_BUF_LEN];
u8 nicbuf_tx[NIC_BUF_LEN];
u32 txlen, rvlen;
u32 txtotal, rvtotal;
tx_desc *pdesc_tx;
rv_desc *pdesc_rv;

u32 pre_rvindex;
u32 pre_rvbuf;

rv_desc descbuf_rv[4096];
u32 pre_rdt;
u32 pre_rdh;
u32 pre_tdt;

//just for test
static void print_str(u8* str, u32 len){
	u32 i = 0;
	for(; i < len; i++){
		print("%c", str[i]);
	}
	print("\n");
}

static void handle_tx_pagefault(u32 index) {
	tx_desc desc;

	read_phymem(IOADDR_BAR0 + TDT, 4, &pre_tdt);
	//print("index=%08x", index);
	//print("pre_tdt=%08x\n", pre_tdt);
	if (index > pre_tdt){
		for(; pre_tdt < index; pre_tdt++){
			
			read_phymem((u32)(pdesc_tx+pre_tdt), 16, &desc);
			//print("length=%08x\n",desc.length);
			if (desc.length > 0){
				if (txtotal +desc.length >= NIC_BUF_LEN){
					#ifdef NIC_WRITE_FILE
					nic_file_write( WRITE_FILE_TX, nicbuf_tx,txtotal);
					#else
					print_str(nicbuf_tx, txtotal);
					#endif
					
					txtotal = 0;
					goto end;
				}
				read_phymem(u64low_to_u32(desc.bufaddr), desc.length, nicbuf_tx+txtotal);
				txtotal+=desc.length;
			}
		}
	}
	else if (index < pre_tdt){
		for(; pre_tdt < txlen; pre_tdt++){
			read_phymem((u32)(pdesc_tx+pre_tdt),16, &desc);
			if (desc.length > 0){
				if (txtotal +desc.length >= NIC_BUF_LEN){
					#ifdef NIC_WRITE_FILE
					nic_file_write( WRITE_FILE_TX, nicbuf_tx,txtotal);
					#else
					print_str(nicbuf_tx, txtotal);
					#endif

					txtotal = 0;
					goto end;
				}
				read_phymem(u64low_to_u32(desc.bufaddr), desc.length, nicbuf_tx+txtotal);
				txtotal+=desc.length;
			}
		}
		pre_tdt = 0;
		for(; pre_tdt < index; pre_tdt++){
			read_phymem((u32)(pdesc_tx+pre_tdt),16, &desc);
			if (desc.length > 0){
				if (txtotal +desc.length >= NIC_BUF_LEN){
					#ifdef NIC_WRITE_FILE
					nic_file_write( WRITE_FILE_TX, nicbuf_tx,txtotal);
					#else
					print_str(nicbuf_tx, txtotal);
					#endif
					
					txtotal = 0;
					goto end;
				}
				read_phymem(u64low_to_u32(desc.bufaddr), desc.length, nicbuf_tx+txtotal);
				txtotal+=desc.length;
			}
		}
	}
	
	end:
		pre_tdt = index;
	/*read_phymem((u32)(pdesc_tx + index), sizeof(desc), desc.value);
	if (desc.length != 0 && u64low_to_u32(desc.bufaddr) != 0) {
		if (txtotal + desc.length >= NIC_BUF_LEN) {
			__asm { int 3 }
			return;
		}
		read_phymem(u64low_to_u32(desc.bufaddr), desc.length, nicbuf + txtotal);
		//nicbuf[desc.length] = '\0';
		txtotal += desc.length;
		print("TxIndex=%08x Len=%d Total=%d\n", index, desc.length, txtotal);
	}*/
}

static void handle_rv_pagefault(u32 index) {
	rv_desc_ext desc_wb[1];
	u32 rdh;
	u32 wb_len;
	//u32 temp, temp1;
	//copy the decriptor
	//__asm{ int 3 }
	//temp = (u32)(pdesc_rv + pre_rdt);
	//temp1 = (u32)(descbuf_rv + pre_rdt);
	read_phymem(IOADDR_BAR0 + RDT, 4, &pre_rdt);
	
	if (index > pre_rdt){
		read_phymem((u32)(pdesc_rv + pre_rdt), (index-pre_rdt)<<4, (descbuf_rv + pre_rdt));
	}else if (index < pre_rdt){
		read_phymem((u32)(pdesc_rv + pre_rdt), (rvlen-pre_rdt)<<4, (descbuf_rv + pre_rdt));
		read_phymem((u32)(pdesc_rv), index << 4, descbuf_rv);
	}
	pre_rdt = index;
	
	read_phymem(IOADDR_BAR0 + RDH, 4, &rdh);
	if (rdh > pre_rdh){
		for (;pre_rdh < rdh; pre_rdh++){
			read_phymem((u32)(pdesc_rv + pre_rdh), 16, desc_wb);
			wb_len = desc_wb[0].wb.upper.length;
			if (wb_len != 0 && u64low_to_u32(descbuf_rv[pre_rdh].bufaddr) != 0){
				if (rvtotal + wb_len >= NIC_BUF_LEN) {
					#ifdef NIC_WRITE_FILE
					nic_file_write( WRITE_FILE_RV, nicbuf_rv, rvtotal);
					#else
					print_str(nicbuf_rv, rvtotal);
					#endif
					rvtotal = 0;
					//goto end;
				}
				read_phymem(u64low_to_u32(descbuf_rv[pre_rdh].bufaddr), wb_len, nicbuf_rv+rvtotal);
				rvtotal += wb_len;
				
			}
		}
	}else if (rdh < pre_rdh){
		//__asm { int 3 }
/*		for (;pre_rdh < rvlen; pre_rdh++){
			read_phymem((u32)(pdesc_rv + pre_rdh), 16, desc_wb);
			wb_len = desc_wb[0].wb.upper.length;
			if (wb_len != 0 && u64low_to_u32(descbuf_rv[pre_rdh].bufaddr) != 0){
				if (rvtotal + wb_len >= NIC_BUF_LEN) {
					//__asm { int 3 }
					print_str(nicbuf_rv, rvtotal);
					rvtotal = 0;
					goto end;
				}
				read_phymem(u64low_to_u32(descbuf_rv[pre_rdh].bufaddr), wb_len, nicbuf_rv+rvtotal);
				rvtotal+=wb_len;
				
				//print("RvIndex=%08x Len=%d Total=%d\n", index, wb_len, rvtotal);
			}
		}
		pre_rdh = 0;
		for (;pre_rdh < rdh; pre_rdh++){
			read_phymem((u32)(pdesc_rv + pre_rdh), 16, desc_wb);
			wb_len = desc_wb[0].wb.upper.length;
			if (wb_len != 0 && u64low_to_u32(descbuf_rv[pre_rdh].bufaddr) != 0){
				if (rvtotal + wb_len >= NIC_BUF_LEN) {
					//__asm { int 3 }
					print_str(nicbuf_rv, rvtotal);
					rvtotal = 0;
					goto end;
				}
				read_phymem(u64low_to_u32(descbuf_rv[pre_rdh].bufaddr), wb_len, nicbuf_rv+rvtotal);
				rvtotal+=wb_len;
				
				//print("RvIndex=%08x Len=%d Total=%d\n", index, wb_len, rvtotal);
			}
		}
*/	}

//end:
	pre_rdh = rdh;
	
/*	read_phymem((u32)(pdesc_rv + index), sizeof(desc), desc.value);
	if (desc.length != 0 && u64high_to_u32(desc.bufaddr) != 0) {
		if (txtotal + desc.length >= NIC_BUF_LEN) {
			__asm { int 3 }
			txtotal = 0;
			return;
		}
		read_phymem(u64high_to_u32(desc.bufaddr), desc.length, nicbuf + txtotal);
		//nicbuf[desc.length] = '\0';
		txtotal += desc.length;
		print("RvIndex=%08x Len=%d Total=%d\n", index, desc.length, txtotal);
	}
	*/
}

static BOOLEAN rangecheck(i32 addr, i32 base, i32 off1, i32 off2) {
	return (addr >= base+off1 && addr < base+off2);
}

static void handle_rv_ring_pagefault(u32 addr, u32 data) {
	i32 off;
	ULONG len;

	off = ((i32)addr - (i32)pdesc_rv) % sizeof(rv_desc);
	switch (off) {
	case 0:
		if (data == 0) { 
			__asm{ int 3 } // check the length is written in next 2 trap
			pre_rvbuf = *(u32*)addr;
		}
		break;
	case 12:
		len = data & 0xff;
		if (txtotal + len >= NIC_BUF_LEN) {
			__asm { int 3 }
			return;
		}
		read_phymem(pre_rvbuf, len, nicbuf_rv+ txtotal);
		txtotal += len;		
		break;
	default:
		break;
	}
}

static BOOLEAN NTAPI ept_handle_violation (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
	
	PHYSICAL_ADDRESS gpa,gla;
	ULONG q, inst_len;
	u32 addr, data;
	u32 *paddr;
	
	#if defined(_X86_)
		gpa.LowPart = VmxRead(GUEST_PHYSICAL_ADDRESS);
	    gpa.HighPart = VmxRead(GUEST_PHYSICAL_ADDRESS_HIGH);
	#elif defined(_X64_)
		gpa.QuadPart = VmxRead(GUEST_PHYSICAL_ADDRESS);
	#endif

	gla.QuadPart = VmxRead(GUEST_LINEAR_ADDRESS);
	q = VmxRead(EXIT_QUALIFICATION);
	Trap->RipDelta = 0;
		
	#ifdef EXAMPLE_MEM_DUMP
		return ept_handle_violation_ext(arch, gpa);
	#else
		if (q & EPT_WRITE_VIOLATION) {
			//print("Ept handler: gpa=%08x\n", gpa.QuadPart);
			inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);

			if (emulate_mov(GuestRegs, &data, &paddr) == FALSE) {
				__asm{ int 3 }
			}
			//__asm{ int 3 }

			addr = u64low_to_u32(gpa.QuadPart);
			//if (rangecheck((i32)addr, (i32)pdesc_rv, 0, rvlen*sizeof(rv_desc))) {
				//__asm{ int 3 }
			//	handle_rv_ring_pagefault(addr, data);
				//write_phymem(addr, 4, &data);
			//}
			
			switch (gpa.QuadPart) {
			case IOADDR_BAR0 + TDT:
				//print("TxIndex=%08x\n", data);
				handle_tx_pagefault(data);
				break;
			case IOADDR_BAR0 + RDT:
				//print("RvIndex=%08x\n", data);
				handle_rv_pagefault(data);
				break;
			default:
				//__asm { int 3 }
				break;
			}
			write_guest_mem(paddr, &data);
			Trap->RipDelta = inst_len;
			return TRUE;
		}
	
		DbgPrint("ept_handle_violation():Violation @0x%llx for %c%c%c/%c%c%c\n", gpa.QuadPart,
				(q & EPT_READ_VIOLATION) ? 'r' : '-',
				(q & EPT_WRITE_VIOLATION) ? 'w' : '-',
				(q & EPT_EXEC_VIOLATION) ? 'x' : '-',
				(q & EPT_EFFECTIVE_READ) ? 'r' : '-',
				(q & EPT_EFFECTIVE_WRITE) ? 'w' : '-',
				(q & EPT_EFFECTIVE_EXEC) ? 'x' : '-');
		panic(("EPT violation should not happen"));
		return FALSE;
	#endif
}

static BOOLEAN NTAPI ept_handle_misconfiguration (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
	panic(("EPT misconfiguration should not happen"));
	return FALSE;
}

static BOOLEAN NTAPI VmxDispatchIO (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
	ULONG inst_len;
	io_qual_t q;
	u16 port;
	void *data;
	bool_t updateip;

	if (!Cpu || !GuestRegs)
    	return TRUE;

	print("Enter IO instruction handler\n");

	//__asm{int 3}

	inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);

	q.ioq = VmxRead(EXIT_QUALIFICATION);
	print("ioq=%08x\n", q.ioq);

	if (q.port == KBD_DATA) {
		u8 key;
		int c;

		//spinlock_lock (&keyboard_lock);
	//retry:
		key = keyboard_getkey ();
		c = keycode_to_ascii (key);
		print("scancode=%02x ascii=%02x\n", key, c);
		//if (c < 0)
		//	goto retry;
		//spinlock_unlock (&keyboard_lock);
		
		GuestRegs->eax = key;		
		if (Trap->RipDelta == 0)
			Trap->RipDelta = inst_len;
		return TRUE;
	}
	
	switch (q.operand) {
	default:
	case EXIT_QUAL_IO_OP_DX:
		port = GuestRegs->edx & 0xFFFF;
		break;
	case EXIT_QUAL_IO_OP_IMMEDIATE:
		port = q.port;
		break;
	}
	switch (q.str) {
	case EXIT_QUAL_IO_STR_NOT_STRING:
		data = &GuestRegs->eax;
		updateip = FALSE;
		switch (q.direction) {
		case EXIT_QUAL_IO_DIR_IN:
			switch (q.size) {
			case EXIT_QUAL_IO_SIZE_1BYTE:
				call_io (IOTYPE_INB, port, data);
				break;
			case EXIT_QUAL_IO_SIZE_2BYTE:
				call_io (IOTYPE_INW, port, data);
				break;
			case EXIT_QUAL_IO_SIZE_4BYTE:
				call_io (IOTYPE_INL, port, data);
				break;
			default:
				panic ("vt_io(IN) unknown size");
			}
			break;
		case EXIT_QUAL_IO_DIR_OUT:
			switch (q.size) {
			case EXIT_QUAL_IO_SIZE_1BYTE:
				call_io (IOTYPE_OUTB, port, data);
				break;
			case EXIT_QUAL_IO_SIZE_2BYTE:
				call_io (IOTYPE_OUTW, port, data);
				break;
			case EXIT_QUAL_IO_SIZE_4BYTE:
				call_io (IOTYPE_OUTL, port, data);
				break;
			default:
				panic ("vt_io(OUT) unknown size");
			}
			break;
		}
		
		if (!updateip && Trap->RipDelta == 0)
			Trap->RipDelta = inst_len;
		break;
	case EXIT_QUAL_IO_STR_STRING:
		/* INS/OUTS can be used with an address-size override
		   prefix.  However, VMCS doesn't have address-size of
		   the I/O instruction. */
		/* we use an interpreter here to avoid the problem */

		//TODO:
		;
	}
	
	return TRUE;
}

static void init_nic_intercept(struct arch_phy* arch) {
	gpaddr_t pgaddr;
	
	read_phymem(IOADDR_BAR0 + TDLEN, 4, &txlen);
	txlen /= sizeof(tx_desc);
	read_phymem(IOADDR_BAR0 + RDLEN, 4, &rvlen);
	rvlen /= sizeof(rv_desc);
	read_phymem(IOADDR_BAR0 + TDBAL, 4, &pdesc_tx); 	
	read_phymem(IOADDR_BAR0 + RDBAL, 4, &pdesc_rv);

	//for decriptor copy
	read_phymem(IOADDR_BAR0 + RDT, 4, &pre_rdt);
	read_phymem(IOADDR_BAR0 + RDH, 4, &pre_rdh);
	
	read_phymem(IOADDR_BAR0 + TDT, 4, &pre_tdt);

	
	pre_rvindex = rvlen;
	pre_rvbuf = NULL;
	txtotal = 0;
	/*arch->p2m.p2m_update_mapping(gpaddr_to_gfn(IOADDR_BAR0 + TDT),
								 gpaddr_to_gfn(IOADDR_BAR0 + TDT),
								 P2M_READABLE|P2M_EXECUTABLE,
								 FALSE,
								 P2M_UPDATE_MT);*/
	/*arch->p2m.p2m_update_mapping(gpaddr_to_gfn(IOADDR_BAR0 + RDT),
								 gpaddr_to_gfn(IOADDR_BAR0 + RDT),
								 P2M_READABLE|P2M_EXECUTABLE,
								 FALSE,
								 P2M_UPDATE_MT);*/
	/*arch->p2m.p2m_update_mapping(gpaddr_to_gfn(IOADDR_BAR0 + RDH),
								 gpaddr_to_gfn(IOADDR_BAR0 + RDH),
								 P2M_READABLE|P2M_EXECUTABLE,
								 FALSE,
								 P2M_UPDATE_MT);*/

	pgaddr = IOADDR_BAR0 + RDT; //(gpaddr_t)pdesc_rv;
	arch->p2m.p2m_update_mapping(gpaddr_to_gfn(pgaddr),
								 gpaddr_to_gfn(pgaddr),
								 P2M_READABLE|P2M_EXECUTABLE,
								 FALSE,
								 P2M_UPDATE_MT);

	pgaddr = IOADDR_BAR0 + TDT; //(gpaddr_t)pdesc_rv;
	arch->p2m.p2m_update_mapping(gpaddr_to_gfn(pgaddr),
								 gpaddr_to_gfn(pgaddr),
								 P2M_READABLE|P2M_EXECUTABLE,
								 FALSE,
								 P2M_UPDATE_MT);
	
	//__asm{int 3}
	#ifdef NIC_WRITE_FILE
		nic_file_create(CREATE_FILE_RV);
		nic_file_create(CREATE_FILE_TX);
	#endif
}

/**
 * effects: Defines the handler of the VM Exit Event which is caused by CPUID.
 * In this function we will return "Hello World!" by pass value through eax,ebx
 * and edx registers.
 */
static BOOLEAN NTAPI VmxDispatchCpuid (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
  ULONG32 fn, eax, ebx, ecx, edx;
  ULONG inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;
  fn = GuestRegs->eax;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->RipDelta == 0)
    Trap->RipDelta = inst_len;

	#ifdef CONFIG_PERF_ENABLE
	if(fn >= PERF_CPUID_BASE && fn <= PERF_CPUID_LIMIT)
	{
		ULONG64 val_from_guest = u32_to_u64(GuestRegs->edx, GuestRegs->ebx);
		ULONG64 val_to_guest;
		
		perf_handle_request(fn, Cpu, val_from_guest, &val_to_guest);

		GuestRegs->eax = u64low_to_u32(val_to_guest);
		GuestRegs->edx = u64high_to_u32(val_to_guest);
		return TRUE;
	}
	#endif
	
	if (fn == BP_KNOCK_EAX) 
  	{
  		Print(("Helloworld:Magic knock received: %p\n", BP_KNOCK_EAX));
    	GuestRegs->eax = BP_KNOCK_EAX_ANSWER;
		GuestRegs->ebx = BP_KNOCK_EBX_ANSWER;
		GuestRegs->edx = BP_KNOCK_EDX_ANSWER;

		//FIXME: maybe it causes some problems after calling this method
		// only for testing and getting BAR0
		//pci_find_devices();					

		// mark NIC buffer as readonly, should be called after identity table created
		init_nic_intercept(arch);
		
    	return TRUE;
  	}
	#ifdef CONFIG_P2M_HIDE_CODE_DATA
	else if(fn == CPUID_EPT_HIDE_VISCODE)
	{
		//PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)GuestRegs->ecx;
		//ULONG32 eip = GuestRegs->edx;
		//ULONG32 offset = eip & ((1 << PAGE_SHIFT) - 1);

		if(arch->p2m.p2m_create_mapping && !vis_concealed)
		{
			mm_hide_vis_code();
			// [TODO] bad design, we should hide the pages in the initialization method, not waiting later.
			// But it works at current.
			mm_hide_vis_pages(arch);
			vis_concealed = TRUE;
		}
		return TRUE;
	}
	else if(fn == CPUID_EPT_REVEAL_VISCODE)
	{
		if(arch->p2m.p2m_create_mapping && vis_concealed)
		{
			mm_reveal_all_pages();
			vis_concealed = FALSE;
		}
		return TRUE;
	}
	#endif
	
	#ifdef EXAMPLE_MEM_DUMP
		{
			BOOLEAN status;
			
			status = VmxDispatchCpuid_ext(GuestRegs, arch, fn);
			if(status)
				return status;
		}		
	#endif

  ecx = (ULONG) GuestRegs->ecx;
  GetCpuIdInfo (fn, &eax, &ebx, &ecx, &edx);
  GuestRegs->eax = eax;
  GuestRegs->ebx = ebx;
  GuestRegs->ecx = ecx;
  GuestRegs->edx = edx;
  
  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchVmxInstrDummy (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
  ULONG32 inst_len;
  ULONG32 addr;
  
  if (!Cpu || !GuestRegs)
    return TRUE;
  Print(("VmxDispatchVminstructionDummy(): Nested virtualization not supported in this build!\n"));

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  Trap->RipDelta = inst_len;

  addr = GUEST_RIP;
  Print(("VmxDispatchVminstructionDummy(): GUEST_RIP 0x%X: 0x%llX\n", addr, VmxRead (addr)));
  addr = VM_EXIT_INTR_INFO;
  Print(("VmxDispatchVminstructionDummy(): EXIT_INTR 0x%X: 0x%llX\n", addr, VmxRead (addr)));
  addr = EXIT_QUALIFICATION;
  Print(("VmxDispatchVminstructionDummy(): QUALIFICATION 0x%X: 0x%llX\n", addr, VmxRead (addr)));
  addr = EXCEPTION_BITMAP;
  Print(("VmxDispatchVminstructionDummy(): EXCEPTION_BITMAP 0x%X: 0x%llX\n", addr, VmxRead (addr)));

  //VmxWrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & (~0x8d5) | 0x1 /* VMFailInvalid */ );
  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchINVD (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
  ULONG inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->RipDelta == 0)
    Trap->RipDelta = inst_len;

  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchMsrRead (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
  LARGE_INTEGER MsrValue;
  ULONG32 ecx;
  ULONG inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->RipDelta == 0)
    Trap->RipDelta = inst_len;

  ecx = GuestRegs->ecx;

  switch (ecx) 
  {
  case MSR_IA32_SYSENTER_CS:
    MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_CS);
    break;
  case MSR_IA32_SYSENTER_ESP:
    MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_ESP);
    break;
  case MSR_IA32_SYSENTER_EIP:
    MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_EIP);
    Print(("VmxDispatchMsrRead(): Guest EIP: 0x%x read MSR_IA32_SYSENTER_EIP value: 0x%x \n", 
        VmxRead(GUEST_RIP), 
        MsrValue.QuadPart));
    break;
  case MSR_GS_BASE:
    MsrValue.QuadPart = VmxRead (GUEST_GS_BASE);
    break;
  case MSR_FS_BASE:
    MsrValue.QuadPart = VmxRead (GUEST_FS_BASE);
    break;
  case MSR_EFER:
    MsrValue.QuadPart = Cpu->Vmx.GuestEFER;
    //_KdPrint(("Guestip 0x%llx MSR_EFER Read 0x%llx 0x%llx \n",VmxRead(GUEST_RIP),ecx,MsrValue.QuadPart));
    break;
  default:
    if (ecx <= 0x1fff
        || (ecx >= 0xC0000000 && ecx <= 0xC0001fff))
    {
        MsrValue.QuadPart = MsrRead (ecx);
    }
  }

  GuestRegs->eax = MsrValue.LowPart;
  GuestRegs->edx = MsrValue.HighPart;

  return TRUE;
}


static BOOLEAN NTAPI VmxDispatchMsrWrite (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
  LARGE_INTEGER MsrValue;
  ULONG32 ecx;
  ULONG inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->RipDelta == 0)
    Trap->RipDelta = inst_len;

  ecx = GuestRegs->ecx;

  MsrValue.LowPart = (ULONG32) GuestRegs->eax;
  MsrValue.HighPart = (ULONG32) GuestRegs->edx;

  switch (ecx) 
  {
  case MSR_IA32_SYSENTER_CS:
    VmxWrite (GUEST_SYSENTER_CS, MsrValue.QuadPart);
    break;
  case MSR_IA32_SYSENTER_ESP:
    VmxWrite (GUEST_SYSENTER_ESP, MsrValue.QuadPart);
    break;
  case MSR_IA32_SYSENTER_EIP:
    VmxWrite (GUEST_SYSENTER_EIP, MsrValue.QuadPart);
    Print(("VmxDispatchMsrRead(): Guest EIP: 0x%x want to write MSR_IA32_SYSENTER_EIP value: 0x%x \n", 
        VmxRead(GUEST_RIP), 
        MsrValue.QuadPart));
    break;
  case MSR_GS_BASE:
    VmxWrite (GUEST_GS_BASE, MsrValue.QuadPart);
    break;
  case MSR_FS_BASE:
    VmxWrite (GUEST_FS_BASE, MsrValue.QuadPart);
    break;
  case MSR_EFER:
    //_KdPrint(("Guestip 0x%llx MSR_EFER write 0x%llx 0x%llx\n",VmxRead(GUEST_RIP),ecx,MsrValue.QuadPart)); 
    Cpu->Vmx.GuestEFER = MsrValue.QuadPart;
    MsrWrite (MSR_EFER, (MsrValue.QuadPart) | EFER_LME);
    break;
  default:
    if (ecx <= 0x1fff
        || (ecx >= 0xC0000000 && ecx <= 0xC0001fff))
    {
        MsrWrite (ecx, MsrValue.QuadPart);
    }
  }

  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchCrAccess (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  struct arch_phy* arch
)
{
    ULONG32 exit_qualification;
    ULONG32 gp, cr;
    ULONG value;
    ULONG inst_len;

    if (!Cpu || !GuestRegs)
        return TRUE;

#if DEBUG_LEVEL>2
    Print(("VmxDispatchCrAccess()\n"));
#endif

    inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
    if (Trap->RipDelta == 0)
        Trap->RipDelta = inst_len;

    //For MOV CR, the general-purpose register:
    //  0 = RAX
    //  1 = RCX
    //  2 = RDX
    //  3 = RBX
    //  4 = RSP
    //  5 = RBP
    //  6 = RSI
    //  7 = RDI
    //  8¨C15 represent R8-R15, respectively (used only on processors that support
    //  Intel 64 architecture)
    exit_qualification = (ULONG32) VmxRead (EXIT_QUALIFICATION);
    gp = (exit_qualification & CONTROL_REG_ACCESS_REG) >> 8;
    cr = exit_qualification & CONTROL_REG_ACCESS_NUM;

#if DEBUG_LEVEL>1
    Print(("VmxDispatchCrAccess(): gp: 0x%x cr: 0x%x exit_qualification: 0x%x\n", gp, cr, exit_qualification));
#endif

    //Access type:
    //  0 = MOV to CR
    //  1 = MOV from CR
    //  2 = CLTS
    //  3 = LMSW
    switch (exit_qualification & CONTROL_REG_ACCESS_TYPE) 
    {
    case TYPE_MOV_TO_CR:

        if (cr == 3) 
        {
        	#ifdef CONFIG_PERF_ENABLE
				Trap->cr3_read_write_ctl = CR3_WRITE_HANDLING;
			#endif
			
        	#ifdef EXAMPLE_MEM_DUMP
        		VmxDispatchCrAccess_ext(arch);
			#endif
            Cpu->Vmx.GuestCR3 = *(((PULONG) GuestRegs) + gp);

            if (Cpu->Vmx.GuestCR0 & X86_CR0_PG)       //enable paging
            {
#if DEBUG_LEVEL>2
                Print(("VmxDispatchCrAccess(): TYPE_MOV_TO_CR cr3:0x%x\n", *(((PULONG64) GuestRegs) + gp)));
#endif
                VmxWrite (GUEST_CR3, Cpu->Vmx.GuestCR3);

            }
            return TRUE;
        }
		
        break;
    case TYPE_MOV_FROM_CR:
        if (cr == 3) 
        {
        	#ifdef CONFIG_PERF_ENABLE
			Trap->cr3_read_write_ctl = CR3_READ_HANDLING;
			#endif
			
            value = Cpu->Vmx.GuestCR3;
#if DEBUG_LEVEL>2
            Print(("VmxDispatchCrAccess(): TYPE_MOV_FROM_CR cr3:0x%x\n", value));
#endif
            *(((PULONG32) GuestRegs) + gp) = (ULONG32) value;

        }
        break;
    case TYPE_CLTS:
        break;
    case TYPE_LMSW:
        break;
    }

    return TRUE;
}


