#pragma once
#include <vis/vcpu.h>
#include <vis/types.h>

#define inline __inline

#define KBD_DATA	0x60
#define KBD_STATUS	0x64

#define IOADDR_BAR0		0xf7be0000	// hard code here

#define STATUS		0x00008
#define TDBAL		0x03800
#define TDBAH		0x03804
#define TDLEN		0x03808
#define TDH			0x03810
#define TDT			0x03818
#define RDBAL		0x02800
#define RDBAH		0x02804
#define RDLEN		0x02808
#define RDH			0x02810
#define RDT			0x02818

#define NIC_BUF_LEN 1600


typedef union {
	struct {
		u16 size		:	3,
		direction		:	1,
		str				:	1,
		rep				:	1,
		operand			:	1,
		avail1			:	9,
		port			:	16;
	};
	u32	ioq;
} io_qual_t;

#pragma pack(1)
typedef union {
	struct {
		u64 bufaddr;
		u16 length;
		u8 cso;
		u8 cmd;
		u8 status;
		u8 rsv;
		u8 css;
		u8 special;
	};
	u64 value[2];
} tx_desc;

typedef union {
	struct {
        u64 bufaddr;
        u16 length;
        u16 checksum;
        u8 status;
        u8 errors;
        u16 special;
	};
	u64 value[2];
} rv_desc;

typedef union {
	struct {
		u64 buffer_addr;
		u64 reserved;
	} read;
	struct {
		struct {
			u32 mrq;	/* Multiple Rx Queues */
			union {
				u32 rss;	/* RSS Hash */
				struct {
					u16 ip_id;	/* IP id */
					u16 csum;	/* Packet Checksum */
				} csum_ip;
			} hi_dword;
		} lower;
		struct {
			u32 status_error;	/* ext status/error */
			u16 length;
			u16 vlan;	/* VLAN tag */
		} upper;
	} wb;			/* writeback */
	u64 value[2];
} rv_desc_ext;
#pragma pack()

enum iotype {
	IOTYPE_INB,
	IOTYPE_INW,
	IOTYPE_INL,
	IOTYPE_OUTB,
	IOTYPE_OUTW,
	IOTYPE_OUTL,
};

enum exit_qual_io_dir {
	EXIT_QUAL_IO_DIR_OUT = 0,
	EXIT_QUAL_IO_DIR_IN = 1,
};

enum exit_qual_io_op {
	EXIT_QUAL_IO_OP_DX = 0,
	EXIT_QUAL_IO_OP_IMMEDIATE = 1,
};

enum exit_qual_io_rep {
	EXIT_QUAL_IO_REP_NOT_REP = 0,
	EXIT_QUAL_IO_REP_REP = 1,
};

enum exit_qual_io_size {
	EXIT_QUAL_IO_SIZE_1BYTE = 0,
	EXIT_QUAL_IO_SIZE_2BYTE = 1,
	EXIT_QUAL_IO_SIZE_4BYTE = 3,
};

enum exit_qual_io_str {
	EXIT_QUAL_IO_STR_NOT_STRING = 0,
	EXIT_QUAL_IO_STR_STRING = 1,
};

void set_iobmp (PCPU v, u16 port, bool_t bit);
void do_iopass_default (enum iotype type, u16 port, void *data);
void call_io (enum iotype type, u16 port, void *data);

u8 keyboard_getkey ();
int keycode_to_ascii (u8 key);
int keyboard_getchar ();

static void asm_in8(u16 port, u8 *data) {
	u8 tmp;
	__asm{
		push dx
		mov dx, port
		in al, dx
		mov tmp, al
		pop dx
	}
	*data = tmp;
}

static void asm_in16(u16 port, u16 *data) {
	u16 tmp;
	__asm{
		push dx
		mov dx, port
		in ax, dx
		mov tmp, ax
		pop dx
	}
	*data = tmp;
}

static void asm_in32(u16 port, u32 *data) {
	u32 tmp;
	__asm{
		push dx
		mov dx, port
		in eax, dx
		mov tmp, eax
		pop dx
	}
	*data = tmp;
}

static void asm_out8 (u16 port, u8 data) {
	__asm{
		push dx
		mov al, data
		mov dx, port
		out dx, al
		mov data, al
		pop dx
	}
}

static void
asm_out16 (u16 port, u16 data) {
	__asm{
		push dx
		mov ax, data
		mov dx, port
		out dx, ax
		mov data, ax
		pop dx
	}
}

static void
asm_out32 (u16 port, u32 data) {
	__asm{
		push dx
		mov eax, data
		mov dx, port
		out dx, eax
		mov data, eax
		pop dx
	}
}

void read_phymem(u32 addr, ULONG len, PVOID first);
void write_phymem(u32 addr, ULONG len, PVOID first);

void write_guest_mem(u32 *dst, u32 *src);



BOOLEAN emulate_mov(PGUEST_REGS GuestRegs, u32 *pdata, u32 **paddr);

#ifdef NIC_WRITE_FILE
NTSTATUS NTAPI nic_file_create(ULONG32 cmd);
VOID NTAPI nic_init(void);
NTSTATUS NTAPI nic_file_write(ULONG32 cmd, VOID *content, ULONG content_size);
VOID NTAPI nic_finish(void);
VOID NTAPI nic_finalize(void);

#define CREATE_FILE_TX  1
#define WRITE_FILE_TX 	2
#define CLOSE_FILE_TX 	3
#define CREATE_FILE_RV  4
#define WRITE_FILE_RV 	5
#define CLOSE_FILE_RV 	6

#endif


