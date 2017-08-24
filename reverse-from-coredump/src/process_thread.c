#include "elf_binary.h"
#include "access_memory.h"
#include "disassemble.h"
#include "thread_selection.h"
#include "reverse_log.h"
//#include "insthandler.h"

// verify the current instruction is executable
int pc_executable(elf_core_info* core_info, struct elf_prstatus thread){
       int exec = 1;
       Elf32_Addr address; 
       address = thread.pr_reg[EIP]; 
       if (!address_executable(core_info, address)){
               LOG(stdout, "STATE: The PC value 0x%x of thread is illegal\n", (unsigned int)address);
               exec = 0;       
       }
       return exec;
}


// verify whether one operand is legal access
int single_op_legal_access(cs_insn *insn, cs_x86_op *op, struct elf_prstatus thread, elf_core_info *core_info){
	// according to index/base register and rw property of operand,
	// identify one operand is legal or not
	int legal = 1;
	Elf32_Addr base, index, target;

	if (op->type == X86_OP_MEM) {
		get_value_of_register(op->mem.base, &base, thread);
		get_value_of_register(op->mem.index, &index, thread);
		
		//LOG(stdout, "value of base %x and index %x\n", base, index);

		target = base + index * (unsigned int) op->mem.scale + op->mem.disp;

		if (address_segment(core_info, target) < 0){
			legal = 0;
		}

		if ((op->access & CS_AC_WRITE) && (!address_writable(core_info, target))) {
			legal = 0;
		}
	}
	return legal;
}


// verify whether all the operands are legal access
int op_legal_access(cs_insn *inst, struct elf_prstatus thread, elf_core_info* core_info){
	int count, i;
	cs_x86 *x86;
	cs_x86_op *op;

	if (inst->detail == NULL)
		return;

	x86 = &(inst->detail->x86);

	// loop all the operands
	for (i = 0; i < x86->op_count; i++) {
		op = &(x86->operands[i]);
		if (!single_op_legal_access(inst, op, thread, core_info)) {
			re_ds.root = op;
			return 0;
		}
	}
	return 1;
}

// according to instruction type, add essential implicit operand
// if the libdisassembler does not provide
void add_essential_implicit_operand(cs_insn *inst) {
/*
	// for example, add [esp] operand to push instruction;
	x86_op_t espmem;
	x86_op_t *esp;

	switch (inst->type) {
		case insn_push:
			esp = x86_implicit_operand_1st(inst);
			INIT_ESPMEM(&espmem, op_expression, op_dword, op_write, esp);
			add_new_implicit_operand(inst, &espmem);
			break;
	}
*/
}

// verify whether the current instruction is legal access
int pc_legal_access(elf_core_info* core_info, elf_binary_info *bin_info, struct elf_prstatus thread){
	int legal_access;
	Elf32_Addr address;
	int offset;
	char inst_buf[INST_LEN];
	cs_insn inst;

	// note multiarchitecture
	address = thread.pr_reg[EIP];
	offset = get_offset_from_address(core_info, address);

	if ((offset == ME_NMAP) || (offset == ME_NMEM)){
		LOG(stdout, "DEBUG: The offset of this pc cannot be obtained\n");
		return 0;
	}

	if (offset == ME_NDUMP){
		if (get_data_from_specified_file(core_info, bin_info, address, inst_buf, INST_LEN) < 0)
			return 0;
	}

	if (offset >= 0)
		get_data_from_core((Elf32_Addr)offset, INST_LEN, inst_buf);

	if (disasm_one_inst(inst_buf, INST_LEN, address, &inst) < 0){
		LOG(stdout, "DEBUG: The PC points to an error position\n");
		return 0;
	}

	// if this implicit operand is not in the operand list,
	// add it by ourselves
	add_essential_implicit_operand(&inst);

	if (!op_legal_access(&inst, thread, core_info)){
		return 0;
	}
	return 1;
}

// verify whether one thread crashes
int is_thread_crash(elf_core_info* core_info, elf_binary_info* bin_info, struct elf_prstatus thread){
	int crash  = 0;

	if (!pc_executable(core_info, thread)){
		crash = 1;
		goto out;
	}

	if (!pc_legal_access(core_info,bin_info, thread)){
		crash = 1;
		goto out;
	}
out:
	return crash;
}

// select the thread that leads to crash
// this will be the first step of analysis
int select_thread(elf_core_info* core_info, elf_binary_info * bin_info){
	int crash_num = -1;
	int thread_num = core_info->note_info->core_thread.thread_num;
	int i = 0;
	LOG(stdout, "STATE: Determining The Thread Leading To Crash\n");

	// multiple threads exist
	for (i=0; i<thread_num; i++){
		if (is_thread_crash(core_info, bin_info, core_info->note_info->core_thread.threads_status[i])){
			crash_num = i;
			break;
		}
	}

	if (crash_num == -1)
		LOG(stderr, "Error: Could not determine the crash thread\n");
	else
		LOG(stdout, "DEBUG: The number of the crashing thread is %d\n", crash_num);

	return crash_num;
}
