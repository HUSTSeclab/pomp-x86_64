#ifndef __INST_DATA__
#define __INST_DATA__

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <capstone/capstone.h>

#include "global.h"


typedef struct memseg_struct{
	unsigned low;
	unsigned high;
	void *data;
}memseg_t;

typedef struct corereg_struct{
	elf_gregset_t regs;
	long xmm_reg[32];
	unsigned gs_base;
}corereg_t;

typedef struct coredata_struct{
	size_t memsegnum;
	memseg_t *coremem;
	corereg_t corereg;
}coredata_t;

typedef union valset_struct{
	unsigned char byte; 	 /* 1-byte */
	unsigned short word; 	 /* 2-byte */
	unsigned long dword; 	 /* 4-byte */
	unsigned long qword[2];	 /* 8-byte */
	unsigned long dqword[4]; /* 16-byte*/
}valset_u; 

#define MAX_REG_IN_INST 0x6

typedef struct opv{
	int reg_num; 
	valset_u val; 
}opv_t;

typedef struct operand_val{
	size_t regnum; 
	opv_t regs[MAX_REG_IN_INST];
}operand_val_t; 

typedef struct opval_list{
	int log_num; 
	operand_val_t *opval_list;
}opval_list_t; 


coredata_t *load_coredump(elf_core_info *core_info, elf_binary_info *binary_info);

unsigned long load_trace(elf_core_info *core_info, elf_binary_info *binary_info, char *trace_file, cs_insn *inst);

unsigned long load_log(char *log_path, operand_val_t *oploglist);

bool verify_useless_inst(cs_insn *inst);

void destroy_instlist(cs_insn *instlist);
#endif
