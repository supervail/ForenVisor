#include <vis/io.h>

void set_iobmp(PCPU v, u16 port, bool_t bit) {
	u8 *p;

	port &= 0xFFFF;
	p = (port >> 15) ? (u8 *)v->Vmx.IOBitmapB : (u8 *)v->Vmx.IOBitmapA;
	port &= 0x7FFF;
	if (bit)
		p[port >> 3] |= 1 << (port & 7);
	else
		p[port >> 3] &= ~(1 << (port & 7));

}

/* For INs, we should pass an address to store the data */
/* For OUTs, we only need send the data to be outputed */
void do_iopass_default (enum iotype type, u16 port, void *data) {
	switch (type) {
	case IOTYPE_INB:
		asm_in8 (port, (u8 *)data);
		break;
	case IOTYPE_INW:
		asm_in16 (port, (u16 *)data);
		break;
	case IOTYPE_INL:
		asm_in32 (port, (u32 *)data);
		break;
	case IOTYPE_OUTB:
		asm_out8 (port, *(u8 *)data);
		break;
	case IOTYPE_OUTW:
		asm_out16 (port, *(u16 *)data);
		break;
	case IOTYPE_OUTL:
		asm_out32 (port, *(u32 *)data);
		break;
	default:
		panic ("Fatal error: do_iopass_default: Bad type");
	}		
}

void call_io (enum iotype type, u16 port, void *data) {
	do_iopass_default(type, port, data);
}
