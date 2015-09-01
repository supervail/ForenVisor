/*
 * Copyright (c) 2007, 2008 University of Tsukuba
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the University of Tsukuba nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file	drivers/pci_init.c
 * @brief	PCI driver (init)
 * @author	T. Shinagawa
 */
#include <vis/pci.h>
#include <vis/pci_internal.h>
#include <vis/pci_init.h>
//#include "pci_conceal.h"

static const char driver_name[] = "pci_driver";

static pci_config_address_t pci_make_config_address(int bus, int dev, int fn, int reg)
{
	pci_config_address_t addr;

	addr.allow = 1;
	addr.reserved = 0;
	addr.bus_no = bus;
	addr.device_no = dev;
	addr.func_no = fn;
	addr.reg_no = reg;
	addr.type = 0;
	return addr;
}

static u32 pci_get_base_address_mask(pci_config_address_t addr)
{
	u32 tmp, mask;

	tmp = pci_read_config_data32_without_lock(addr, 0);
	pci_write_config_data_port_without_lock(0xFFFFFFFF);
	mask = pci_read_config_data_port_without_lock();
	pci_write_config_data_port_without_lock(tmp);
	return mask;
}

/*static void pci_save_base_address_masks(struct pci_device *dev)
{
	int i;
	pci_config_address_t addr = dev->address;

	for (i = 0; i < PCI_CONFIG_BASE_ADDRESS_NUMS; i++) {
		addr.reg_no = PCI_CONFIG_ADDRESS_GET_REG_NO(base_address) + i;
		dev->base_address_mask[i] = pci_get_base_address_mask(addr);
	}
	addr.reg_no = PCI_CONFIG_ADDRESS_GET_REG_NO(ext_rom_base);
	dev->base_address_mask[6] = pci_get_base_address_mask(addr);
}*/

static void pci_read_config_space(struct pci_device *dev)
{
	int i;
	pci_config_address_t addr = dev->address;
	struct pci_config_space *cs = &dev->config_space;

//	for (i = 0; i < PCI_CONFIG_REGS32_NUM; i++) {
	for (i = 0; i < 16; i++) {
		addr.reg_no = i;
		cs->regs32[i] = pci_read_config_data32_without_lock(addr, 0);
	}

	// only focus our networks card
	if (dev->address.device_no == 25) {
		__asm { int 3 }
		print("bn=%d dn=%d fn=%d\n", dev->address.bus_no, dev->address.device_no, dev->address.func_no);
		print("bar0=%08x bar1=%08x bar2=%08x\n", cs->base_address[0], cs->base_address[1], cs->base_address[2]);
	}
}

static struct pci_device *pci_new_device(pci_config_address_t addr)
{
	struct pci_device tmp, *dev;
	
	dev = &tmp; //dev = alloc_pci_device();
	if (dev != NULL) {		
		RtlZeroMemory(dev, sizeof(*dev)); //memset(dev, 0, sizeof(*dev));
		dev->driver = NULL;
		dev->address = addr;
		pci_read_config_space(dev);
		//pci_save_base_address_masks(dev);
		//dev->conceal = pci_conceal_new_device (dev);
		//pci_append_device(dev);
	}
	return dev;
}

struct pci_device *
pci_possible_new_device (pci_config_address_t addr)
{
	u16 data;
	struct pci_device *ret = NULL;

	data = pci_read_config_data16_without_lock (addr, 0);
	if (data != 0xFFFF)
		ret = pci_new_device (addr);
	return ret;
}

void pci_find_devices()
{
	int bn, dn, fn, num = 0;
	struct pci_device *dev;
	pci_config_address_t addr, old;
	u16 data;

	Print("PCI: finding devices ");	
	//asm_in32(PCI_CONFIG_ADDR_PORT, &old.value); //pci_save_config_addr();
	__asm {int 3}
	for (bn = 0; bn < PCI_MAX_BUSES; bn++)
	  for (dn = 0; dn < PCI_MAX_DEVICES; dn++)
	    for (fn = 0; fn < PCI_MAX_FUNCS; fn++) {
		addr = pci_make_config_address(bn, dn, fn, 0);
		data = pci_read_config_data16_without_lock(addr, 0);
		
		if (data == 0xFFFF) /* not exist */
			continue;

		dev = pci_new_device(addr);
		//if (dev == NULL)
		//	goto oom;
		//printf("."); num++; 

		if (fn == 0 && 
				0 == (dev->config_space.header_type & 0x80))//dev->config_space.multi_function == 0)
			break;
	    }
		
	//asm_out32(PCI_CONFIG_ADDR_PORT, old.value); //pci_restore_config_addr();
	//printf(" %d devices found\n", num);
	//return;

//oom:
//	panic_oom();
}

/*
static void pci_init()
{
	pci_find_devices();
	core_io_register_handler(PCI_CONFIG_ADDR_PORT, 1, pci_config_addr_handler, NULL,
				 CORE_IO_PRIO_HIGH, driver_name);
	core_io_register_handler(PCI_CONFIG_DATA_PORT, 4, pci_config_data_handler, NULL,
				 CORE_IO_PRIO_HIGH, driver_name);
	return;
}
DRIVER_INIT(pci_init);
*/
