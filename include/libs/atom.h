/****************************
* 2011.1     Miao Yu     Implement Vis hypervisor on x86 and x86_64(not finished). 
                                 Create this file
* 
*****************************/

#pragma once

#define atom_inc(val) __asm \
						{ \
							__asm lock inc [val] \
						}
#define atom_dec(val) __asm \
						{ \
							__asm lock dec [val] \
						}

