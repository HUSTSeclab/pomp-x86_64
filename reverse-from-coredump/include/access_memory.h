#ifndef __ACCESS_MEMORY__
#define __ACCESS_MEMORY__

#include <capstone/capstone.h>

#include "elf_core.h"
#include "elf_binary.h"


int get_value_of_register(x86_reg reg, Elf32_Addr *value, struct elf_prstatus thread);

off_t get_offset_from_address(elf_core_info *core_info, Elf32_Addr address);

int get_data_from_core(long int start, long int size, char *note_data);

int address_segment(elf_core_info *core_info, Elf32_Addr address);

int address_executable(elf_core_info *core_info, Elf32_Addr address);

int address_writable(elf_core_info *core_info, Elf32_Addr address);

int get_data_from_specified_file(elf_core_info *core_info, elf_binary_info *bin_info, Elf32_Addr address, char *buf, size_t buf_size);

#endif
