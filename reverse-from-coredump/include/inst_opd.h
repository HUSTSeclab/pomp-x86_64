#ifndef __INST_OPD__
#define __INST_OPD__

#include "reverse_exe.h"

#define GET_VALUE_OK 0
#define BAD_ADDRESS -1
/*
int get_index_from_x86_reg_t(x86_reg_t reg);

void get_value_from_xmm_reg(x86_reg_t reg, valset_u *value);

int get_regval_from_coredum(x86_reg_t reg, valset_u *value);

int get_memval_from_coredump(re_list_t *entry, valset_u *value);

int get_value_from_coredump(re_list_t *entry, valset_u *value);

int get_immediate_from_opd(x86_op_t *opd, valset_u *value);

void search_value_from_coredump(valset_u searchvalue, enum x86_op_datatype datatype, unsigned **dp, unsigned *num);

x86_op_t * x86_implicit_operand_1st( x86_insn_t *insn );

x86_op_t * x86_implicit_operand_2nd( x86_insn_t *insn );

x86_op_t * x86_implicit_operand_3rd( x86_insn_t *insn );

x86_op_t *x86_implicit_operand_new(x86_insn_t *inst);

x86_op_t *find_implicit_operand(x86_insn_t *insn, x86_op_t *opd);

x86_op_t *add_new_implicit_operand(x86_insn_t *insn, x86_op_t *opd);

void convert_offset_to_exp(x86_op_t *opd);

unsigned search_address_of_value(valset_u vt, enum x86_op_datatype datatype);
*/


cs_x86_op * x86_operand_1st( cs_insn *insn );
cs_x86_op * x86_operand_2nd( cs_insn *insn );
cs_x86_op * x86_operand_3rd( cs_insn *insn );

#define x86_get_dest_operand( insn ) x86_operand_1st( insn )
#define x86_get_src_operand( insn ) x86_operand_2nd( insn )
#define x86_get_imm_operand( insn ) x86_operand_3rd( insn )

#endif
