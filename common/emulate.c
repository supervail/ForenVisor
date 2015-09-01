#include <vis/io.h>

typedef union {
	struct {
		u8 mmm:    3, // RM
		   rrr:    3, // REG
		   oo:     2; // Mod
	};
	u8 value;
} modrm_t;

typedef union {
	struct {
		u8 base:    3,
		   index:	3,
		   scale:   2;
	};
	u8 value;
} sib_t;

u32 *pregs;
u8 *rip;
u32 cur_ripoff, error;

static u32* get_sib_addr(modrm_t modrm, sib_t sib) {
	u32 addr;
	if (modrm.oo == 0 && sib.base == 5) {
		addr = 0;
	} else {
		addr = pregs[sib.base];
	}

	if (sib.index != 4) {
		addr += (pregs[sib.index] << sib.scale);
	}

	return (u32*)addr;
}

static u32* get_modrm_addr(modrm_t modrm) {
	u8 disp8;
	u32 addr, disp32;
	sib_t sib;
	
	addr = pregs[modrm.mmm];

	switch (modrm.oo) {
	case 0:
		if (modrm.mmm == 4) {
			sib.value = rip[cur_ripoff++];
			addr = (u32)get_sib_addr(modrm, sib);
		} else if (modrm.mmm == 5) {
			disp32 = *(u32*)(rip + cur_ripoff);
			addr = disp32;
		}
		break;
	case 1:
		if (modrm.mmm == 4) {
			sib.value = rip[cur_ripoff++];
			addr = (u32)get_sib_addr(modrm, sib);
		}
		disp8 = rip[cur_ripoff];
		addr += disp8;
		break;
	case 2:
		if (modrm.mmm == 4) {
			sib.value = rip[cur_ripoff++];
			addr = (u32)get_sib_addr(modrm, sib);
		}
		disp32 = *(u32*)(rip + cur_ripoff);
		addr += disp32;
		break;
	case 3:
		break;
	default:
		print("Unimplemented case in get_modrm_addr: rip=%08x inst=%d\n", rip, *(u32*)rip);
		error = 1;
		break;
	}

	return (u32*)addr;
}

static void load_cr3(ULONG32 value) {
	__asm{
		mov eax, value
		mov cr3, eax
	}
}

void write_guest_mem(u32 *dst, u32 *src) {
	ULONG32 guest_cr3, host_cr3;

	host_cr3 = VmxRead(HOST_CR3); 
	guest_cr3 = VmxRead(GUEST_CR3);

	//load_cr3(guest_cr3);
	*dst = *src;
	//load_cr3(host_cr3);
}

BOOLEAN emulate_mov(PGUEST_REGS GuestRegs, u32 *pdata, u32 **paddr) {
	//u32 *paddr;
	modrm_t modrm;

	pregs = (u32*)GuestRegs;
	rip = (u8*)VmxRead (GUEST_RIP);
	cur_ripoff = 0;
	
	//__asm { int 3 }
	
	switch(rip[cur_ripoff++]) {
	case 0x89: // mov r/m32,r32
		modrm.value = rip[cur_ripoff++];		
		*pdata = pregs[modrm.rrr];
		*paddr = get_modrm_addr(modrm);

		//write_guest_mem(paddr, data);
		break;
	case 0x8b: // mov r32, r/m32
		modrm.value = rip[cur_ripoff++];		
		*pdata = *(get_modrm_addr(modrm));
		*paddr = pregs + modrm.rrr;

		//write_guest_mem(paddr, data);
		break;
	case 0xc7: // mov r/m32, imm32
		//__asm{ int 3 }
		modrm.value = rip[cur_ripoff++];
		*paddr = get_modrm_addr(modrm);
		*pdata = *(u32*)(rip + cur_ripoff);
		break;
	default:
		__asm{ int 3 }
		print("Unimplemented case in emulate_mov: rip=%08x inst=%d\n", rip, *(u32*)rip);	
		return FALSE;
	}
	return TRUE;
}
