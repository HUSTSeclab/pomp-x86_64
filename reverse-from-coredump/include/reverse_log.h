#ifndef __REVERSE_LOG__
#define __REVERSE_LOG__

#include "reverse_exe.h"


#ifdef DEBUG
#define LOG(...) do { fprintf(__VA_ARGS__); } while (0)
#else
#define LOG(...)
#endif

void print_instnode(inst_node_t *instnode);

void print_assembly(cs_insn *inst);

void print_info_of_current_inst(re_list_t *inst);

void print_operand(cs_x86_op opd);

void print_reg(x86_reg reg);

void print_registers(coredata_t *coredata);

/*
void log_instructions(x86_insn_t *instlist, unsigned instnum);

void print_operand_info(int opd_count, ...);

void print_all_operands(x86_insn_t *inst);

void print_deflist(re_list_t *re_deflist);

void print_uselist(re_list_t *re_uselist);

void print_instlist(re_list_t *re_instlist);

void print_umemlist(re_list_t *re_umemlist);

void print_corelist(re_list_t *re_list);

void alias_print_info_of_current_inst(re_list_t *inst);

void print_value_of_node(valset_u val, enum x86_op_datatype datatype);

void print_usenode(use_node_t *usenode);

void print_defnode(def_node_t *defnode);

void print_node(re_list_t *node);
*/
#endif
