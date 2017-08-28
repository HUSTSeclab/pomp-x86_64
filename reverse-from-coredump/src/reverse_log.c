#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "reverse_log.h"
#include "global.h"
#include "disassemble.h"
#include "insthandler.h"
#include "access_memory.h"
#include "reverse_exe.h"


void print_reg(x86_reg reg) {
	if (reg == X86_REG_INVALID) {
		LOG(stdout, "Reg = NULL");
	} else {
		LOG(stdout, "Reg = %s", cs_reg_name(handle, reg));
	}
}

void print_assembly(cs_insn *inst){
	if (!inst) return;
	LOG(stdout, "Current Instruction is 0x%x" PRIx32 ":\t%s\t%s\n",
	    (unsigned int)RE_X86_INST_ADDR(*inst),
	    RE_X86_INST_MNEMONIC(*inst),
	    RE_X86_INST_OPSTR(*inst));
}

void print_operand(cs_x86_op opd){
	LOG(stdout, "Information for operand: \n");
	switch (RE_X86_OP_ACCESS(opd)) {
	case CS_AC_READ:
		LOG(stdout, "\toperand.access : Read\n");
		break;
	case CS_AC_WRITE:
		LOG(stdout, "\toperand.access : Write\n");
		break;
	}

	switch(RE_X86_OP_TYPE(opd)) {
	case X86_OP_INVALID:
		LOG(stderr, "\t%s\n", "Invalid Operand Type");
		break;
	case X86_OP_REG:
		LOG(stdout, "\toperand.type: ");
		print_reg(RE_X86_REG_ID(opd));
		LOG(stdout, "\n");
		break;
	case X86_OP_IMM:
		LOG(stdout, "\toperand.type: IMM 0x%x\n", (unsigned int)RE_X86_IMM_VALUE(opd));
		break;
	case X86_OP_MEM:
		LOG(stdout, "\toperand.type: MEM\n");
		LOG(stdout, "\toperand.segment: ");
		print_reg(RE_X86_MEM_SEG(opd));
		LOG(stdout, "\n");
		LOG(stdout, "\toperand.mem.base: ");
		print_reg(RE_X86_MEM_BASE(opd));
		LOG(stdout, "\n");
		LOG(stdout, "\toperand.mem.index ");
		print_reg(RE_X86_MEM_INDEX(opd));
		LOG(stdout, "\n");
		LOG(stdout, "\toperand.mem.scale: %u\n", RE_X86_MEM_SCALE(opd));
		LOG(stdout, "\toperand.mem.disp: %x\n", (int)RE_X86_MEM_DISP(opd));

		break;
	}
}

// print all the registers for one instruction
void print_registers(coredata_t *coredata){
    LOG(stdout, "DEBUG: EAX - 0x%lx\n", coredata->corereg.regs[EAX]);
    LOG(stdout, "DEBUG: EBX - 0x%lx\n", coredata->corereg.regs[EBX]);
    LOG(stdout, "DEBUG: ECX - 0x%lx\n", coredata->corereg.regs[ECX]);
    LOG(stdout, "DEBUG: EDX - 0x%lx\n", coredata->corereg.regs[EDX]);
    LOG(stdout, "DEBUG: ESI - 0x%lx\n", coredata->corereg.regs[ESI]);
    LOG(stdout, "DEBUG: EDI - 0x%lx\n", coredata->corereg.regs[EDI]);
    LOG(stdout, "DEBUG: EBP - 0x%lx\n", coredata->corereg.regs[EBP]);
    LOG(stdout, "DEBUG: ESP - 0x%lx\n", coredata->corereg.regs[UESP]);
    LOG(stdout, "\n");
}

void print_all_operands(cs_insn *inst) {
	int count, i;
	cs_x86 *x86;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (inst->detail == NULL)
		return;

	x86 = &(inst->detail->x86);

	if (x86->op_count)
		LOG(stdout, "op_count: %u\n", x86->op_count);
	for (i = 0; i < x86->op_count; i++) {
		print_operand(x86->operands[i]);
	}
}

void print_info_of_instruction(cs_insn *inst) {
	print_assembly(inst);
	print_all_operands(inst);
}

#if 0
void print_value_of_node(valset_u val, enum x86_op_datatype datatype) {
	switch (datatype) {
		case op_byte:
			LOG(stdout, "0x%x (byte)", val.byte);
			break;
		case op_word:
			LOG(stdout, "0x%x (word)", val.word);
			break;
		case op_dword:
			LOG(stdout, "0x%lx (dword)", val.dword);
			break;
		case op_qword:
			LOG(stdout, "0x%lx 0x%lx (qword)",
				val.qword[0], val.qword[1]);
			break;
		case op_dqword:
			LOG(stdout, "0x%lx 0x%lx 0x%lx 0x%lx (dqword)",
				val.dqword[0], val.dqword[1],
				val.dqword[2], val.dqword[3]);
			break;
		
		case op_ssimd:
			LOG(stdout, "0x%lx 0x%lx 0x%lx 0x%lx (dqword)",
                                val.dqword[0], val.dqword[1],
                                val.dqword[2], val.dqword[3]);
                        break;

		default:
			assert("No such datatype" && 0);
	}
}


void print_defnode(def_node_t *defnode){
	LOG(stdout, "LOG: Def Node with opd ");
	print_operand(*(defnode->operand));
	LOG(stdout, "\n");
	switch (defnode->val_stat) {
	case Unknown:
		LOG(stdout, "LOG: Both value are unknown\n");
		break;
	case BeforeKnown:
		LOG(stdout, "LOG: Before value are known\n");
		LOG(stdout, "LOG: Before Value ");
		print_value_of_node(defnode->beforeval, defnode->operand->datatype);
		LOG(stdout, "\n");
		break;
	case AfterKnown:
		LOG(stdout, "LOG: After value are known\n");
		LOG(stdout, "LOG: After  Value ");
		print_value_of_node(defnode->afterval, defnode->operand->datatype);
		LOG(stdout, "\n");
		break;
	case 0x3:
		LOG(stdout, "LOG: Both value are known\n");
		LOG(stdout, "LOG: Before Value ");
		print_value_of_node(defnode->beforeval, defnode->operand->datatype);
		LOG(stdout, "\n");
		LOG(stdout, "LOG: After  Value ");
		print_value_of_node(defnode->afterval, defnode->operand->datatype);
		LOG(stdout, "\n");
		break;
	}
	if (defnode->operand->type == op_expression){
		if (defnode->address != 0) {
			LOG(stdout, "LOG: address = 0x%x\n", defnode->address);
		} else {
			LOG(stdout, "LOG: address is unknown\n");
		}
	}
}


void print_usenode(use_node_t *usenode){
	LOG(stdout, "LOG: Use Node with ");
	switch (usenode->usetype) {
		case Opd:
			LOG(stdout, "Opd itself ");
			print_operand(*(usenode->operand));
			break;
		case Base:
			LOG(stdout, "Base Register ");
			print_reg(usenode->operand->data.expression.base);
			break;
		case Index:
			LOG(stdout, "Index Register ");
			print_reg(usenode->operand->data.expression.index);
			break;
	}
	LOG(stdout, "\n");
	if (usenode->val_known) {
		LOG(stdout, "LOG: Value is known\n");
		LOG(stdout, "LOG: Value ");
		switch (usenode->usetype) {
		case Opd:
			print_value_of_node(usenode->val, usenode->operand->datatype);
			break;
		case Base:
			print_value_of_node(usenode->val, op_dword);
			break;
		case Index:
			print_value_of_node(usenode->val, op_dword);
			break;
		}
		LOG(stdout, "\n");
	} else {
		LOG(stdout, "LOG: Value is unknown\n");
	}
	if ((usenode->usetype == Opd)&&(usenode->operand->type == op_expression)){
		if (usenode->address != 0) {
			LOG(stdout, "LOG: Address = 0x%x\n", usenode->address);
		} else {
			LOG(stdout, "LOG: Address is unknown\n");
		}
	}
}
#endif

void print_instnode(inst_node_t *instnode) {
	LOG(stdout, "LOG: Inst Node with index %d and function ID %x\n", instnode->inst_index, instnode->funcid);
	print_assembly(re_ds.instlist + instnode->inst_index);
}

#if 0
void print_node(re_list_t *node){
	LOG(stdout, "LOG: Node ID is %d\n", node->id);
	switch (node->node_type) {
		case InstNode:
			print_instnode(CAST2_INST(node->node));
			break;
		case UseNode:
			print_usenode(CAST2_USE(node->node));
			break;
		case DefNode:
			print_defnode(CAST2_DEF(node->node));
			break;
		default:
			assert(0);
			break;
	}
}


// only print def list
void print_deflist(re_list_t *re_deflist) {
	re_list_t *entry;
	def_node_t *defnode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of deflist:\n");
	list_for_each_entry_reverse(entry, &re_deflist->deflist, deflist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		defnode = CAST2_DEF(entry->node);
		print_defnode(defnode);
	}
	LOG(stdout, "=================================================\n");
}


// only print use list
void print_uselist(re_list_t *re_uselist) {
	re_list_t *entry;
	use_node_t *usenode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of uselist:\n");
	list_for_each_entry_reverse(entry, &re_uselist->uselist, uselist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		usenode = CAST2_USE(entry->node);
		print_usenode(usenode);
	}
	LOG(stdout, "=================================================\n");
}


// only print inst list
void print_instlist(re_list_t *re_instlist) {
	re_list_t *entry;
	inst_node_t *instnode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of instlist:\n");
	list_for_each_entry_reverse(entry, &re_instlist->instlist, instlist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		instnode = CAST2_INST(entry->node);
		print_instnode(instnode);
	}
	LOG(stdout, "=================================================\n");
}


// In general, re_umemlist should be &re_ds.head
// This linked list is a global list
void print_umemlist(re_list_t *re_umemlist) {
	re_list_t *entry, *inst;
	
	unsigned umemnum = 0;

	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of umemlist:\n");
	list_for_each_entry_reverse(entry, &re_umemlist->umemlist, umemlist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
		inst = find_inst_of_node(entry);
		if (inst) {
			print_instnode(CAST2_INST(inst->node));
		} else {
			assert(0);
		}
		umemnum++;

	}
	LOG(stdout, "%d unknown memory write=================================================\n", umemnum);
}


// heavy print function 
// print all the elements in the core list
void print_corelist(re_list_t *re_list) {
	re_list_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~~Start of Core List~~~~~~~~~~~~~~~~~~~~~~\n");
	list_for_each_entry_reverse(entry, &re_list->list, list) {
		if (entry->node_type == InstNode) LOG(stdout, "\n");
		
		LOG(stdout, "=================================================\n");
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		if (entry->node_type == InstNode) {
			print_instnode(CAST2_INST(entry->node));
		}
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~~~End of Core List~~~~~~~~~~~~~~~~~~~~~~~\n");

}
#endif

// only print all the operands of the current instruction 
void print_info_of_current_inst(re_list_t *inst){
	re_list_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~Start of Current Inst Info~~~~~~~~~~~~~~~~~~~\n");
	LOG(stdout, "LOG: Node ID is %d\n", inst->id);
	print_instnode(inst->node);
	/*
	list_for_each_entry_reverse(entry, &inst->list, list) {
		LOG(stdout, "=================================================\n");
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) break;

		LOG(stdout, "LOG: Node ID is %d\n", entry->id);

		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
	}
	*/
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~End of Current Inst info~~~~~~~~~~~~~~~~~~~~\n");
}

// log all the instructions to one file, called "instructions"
// it will check exist of this file
void log_instructions(cs_insn *instlist, unsigned instnum){

	if (access("instruction", F_OK) != -1) {
		LOG(stdout, "WARNING: instruction file exists, it will be erased\n");
		return;
	} 	

	FILE *file;
	int i;

	if ((file=fopen("instructions", "w")) == NULL) {
		LOG(stderr, "ERROR: instructions file open error\n");
		assert(0);
	}

	for (i=0;i<instnum;i++) {
		LOG(file, "Current Instruction is 0x%" PRIx32 ":\t%s\t%s\n", 
			(unsigned int)instlist[i].address, instlist[i].mnemonic, instlist[i].op_str);
	}
}

#if 0
void print_maxfuncid() {
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Max Function ID is %d\n", maxfuncid());
	LOG(stdout, "=================================================\n");
}
#endif
