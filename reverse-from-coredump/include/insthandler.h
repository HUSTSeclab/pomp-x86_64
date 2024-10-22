#ifndef __INSTHANDLER__
#define __INSTHANDLER__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "disassemble.h"
#include "global.h"
#include "access_memory.h"
#include "reverse_log.h"
#include "reverse_exe.h"
#include "inst_opd.h"
//#include "re_alias.h"
//#include "heuristics.h"

// fetch property from cs_insn pointer
#define RE_X86_INST_TYPE(inst) \
	((inst).id)

#define RE_X86_INST_ADDR(inst) \
	((inst).address)

#define RE_X86_INST_MNEMONIC(inst) \
	((inst).mnemonic)

#define RE_X86_INST_OPSTR(inst) \
	((inst).op_str)

// fetch property from x86_cs_op
#define RE_X86_OP_TYPE(opd) \
	((opd).type)

#define RE_X86_OP_ACCESS(opd) \
	((opd).access)

#define RE_X86_REG_ID(opd) \
	((opd).reg)

#define RE_X86_IMM_VALUE(opd) \
	((opd).imm)

#define	RE_X86_MEM_SEG(opd) \
	((opd).mem.segment)

#define	RE_X86_MEM_BASE(opd) \
	((opd).mem.base)

#define	RE_X86_MEM_INDEX(opd) \
	((opd).mem.index)

#define	RE_X86_MEM_SCALE(opd) \
	((opd).mem.scale)

#define	RE_X86_MEM_DISP(opd) \
	((opd).mem.disp)

//#define x86_opd_is_esp(opd) \
//	((opd)->type == op_register && (strcmp(opd->data.reg.name, "esp") == 0))
//
//#define x86_opd_is_ebp(opd) \
//	((opd)->type == op_register && (strcmp(opd->data.reg.name, "ebp") == 0))
//

typedef struct op_index_pair{
	enum x86_insn type;
	int index;
}op_index_pair_t;

extern op_index_pair_t opcode_index_tab[];

extern const int ninst;

typedef void (*resolver_func)(re_list_t* instnode, re_list_t *re_deflist, re_list_t *re_uselist);

typedef void (*handler_func)(re_list_t * instnode);

typedef int (*esp_resolve_func)(re_list_t *instnode, int *disp);

typedef int (*post_resolve_heuristic_func)(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

extern resolver_func inst_resolver[];

extern handler_func inst_handler[];

extern esp_resolve_func esp_resolver[];

extern post_resolve_heuristic_func post_resolve_heuristics[];

//int translate_datatype_to_byte(enum x86_op_datatype datatype);

#define INIT_ESPMEM(espmem, op_type, op_datatype, op_access, espreg) \
	memset((espmem), 0, sizeof(x86_op_t)); \
	(espmem)->type = op_type; \
	(espmem)->datatype = op_datatype; \
	(espmem)->access = op_access; \
	(espmem)->data.expression.base = espreg->data.reg;

#define INIT_REGOPD(regopd, op_type, op_datatype, op_access, oreg) \
	memset((regopd), 0, sizeof(x86_op_t)); \
	(regopd)->type = op_type; \
	(regopd)->datatype = op_datatype; \
	(regopd)->access = op_access; \
	(regopd)->data.reg = oreg;

#define EXACT_SAME_REG(reg1, reg2) \
	(reg1 == reg2)

#define reg1_alias_reg2(reg1, reg2) \
	(reg1.alias == reg2.id)

#define same_alias(reg1, reg2) \
	((reg1.alias == reg2.alias) && (reg1.alias != 0))

#define exact_same_mem(address1, size1, address2, size2) \
	((address1 == address2) && (size1 == size2))

#define subset_mem(address1, size1, address2, size2) \
	((address1 >= address2) && (address1+size1 <= address2+size2) && (address1 < address1+size1))

#define superset_mem(address1, size1, address2, size2) \
	((address1 <= address2) && (address1+size1 >= address2+size2) && (address2 < address2+size2))

#define overlap_mem(address1, size1, address2, size2) \
	((address1+size1 > address2) && (address1+size1 <= address2+size2))

#define op_with_gs_seg(opd) \
	(((opd)->flags & op_gs_seg) >> 8 == 6)

#define SAME_REG(dest, src) \
	(DST_REG_SRC_REG(dest, src) && EXACT_SAME_REG(RE_X86_REG_ID(dest), RE_X86_REG_ID(src)))

#define DIFF_REGS(dest, src) \
	(DST_REG_SRC_REG(dest, src) && (!EXACT_SAME_REG(RE_X86_REG_ID(dest), RE_X86_REG_ID(src))))

enum expreg_status {
	No_Reg = 0x0,
	Base_Reg,
	Index_Reg,
	Base_Index_Reg
};

/*
static inline enum expreg_status get_expreg_status(x86_ea_t exp){
	if ((exp.base.id != 0) && (exp.index.id != 0)) {
		return Base_Index_Reg;
	}
	if ((exp.base.id != 0) && (exp.index.id == 0)) {
		return Base_Reg;
	}
	if ((exp.base.id == 0) && (exp.index.id != 0)) {
		return Index_Reg;
	}
	if ((exp.base.id == 0) && (exp.index.id == 0)) {
		return No_Reg;
	}
}
*/

enum operand_status {
	dest_register_src_register = 1,
	dest_register_src_expression,
	dest_register_src_imm,
	dest_expression_src_expression,
	dest_expression_src_register,
	dest_expression_src_imm
};

#define RE_X86_OPD_IS_REG(opd) \
	(RE_X86_OP_TYPE(opd) == X86_OP_REG)

#define RE_X86_OPD_IS_EXP(opd) \
	(RE_X86_OP_TYPE(opd) == X86_OP_MEM)

#define RE_X86_OPD_IS_IMM(opd) \
	(RE_X86_OP_TYPE(opd) == X86_OP_IMM)

#define DST_REG_SRC_REG(dest, src) \
	(RE_X86_OPD_IS_REG(dest) && RE_X86_OPD_IS_REG(src))

#define DST_REG_SRC_EXP(dest, src) \
	(RE_X86_OPD_IS_REG(dest) && RE_X86_OPD_IS_EXP(src))

#define DST_REG_SRC_IMM(dest, src) \
	(RE_X86_OPD_IS_REG(dest) && RE_X86_OPD_IS_IMM(src))

#define DST_EXP_SRC_EXP(dest, src) \
	(RE_X86_OPD_IS_EXP(dest) && RE_X86_OPD_IS_EXP(src))

#define DST_EXP_SRC_REG(dest, src) \
	(RE_X86_OPD_IS_EXP(dest) && RE_X86_OPD_IS_REG(src))

#define DST_EXP_SRC_IMM(dest, src) \
	(RE_X86_OPD_IS_EXP(dest) && RE_X86_OPD_IS_IMM(src))

static inline enum operand_status get_operand_combine(cs_insn *inst) {
	cs_x86_op *dest = x86_get_dest_operand(inst);
	cs_x86_op *src = x86_get_src_operand(inst);
	if (DST_REG_SRC_REG(*dest, *src))
		return dest_register_src_register;
	if (DST_REG_SRC_EXP(*dest, *src))
		return dest_register_src_expression;
	if (DST_REG_SRC_IMM(*dest, *src))
		return dest_register_src_imm;
	if (DST_EXP_SRC_EXP(*dest, *src))
		return dest_expression_src_expression;
	if (DST_EXP_SRC_REG(*dest, *src))
		return dest_expression_src_register;
	if (DST_EXP_SRC_IMM(*dest, *src))
		return dest_expression_src_imm;
	assert(0);
}


// instruction handlers
void add_handler(re_list_t *instnode);

void sub_handler(re_list_t *instnode);

void mul_handler(re_list_t *instnode);

void div_handler(re_list_t *instnode);

void inc_handler(re_list_t *instnode);

void dec_handler(re_list_t *instnode);

void shl_handler(re_list_t *instnode);

void shr_handler(re_list_t *instnode);

void rol_handler(re_list_t *instnode);

void ror_handler(re_list_t *instnode);


void and_handler(re_list_t *instnode);

void or_handler(re_list_t *instnode);

void xor_handler(re_list_t *instnode);

void not_handler(re_list_t *instnode);

void neg_handler(re_list_t *instnode);


void call_handler(re_list_t *instnode);

void callcc_handler(re_list_t *instnode);

void return_handler(re_list_t *instnode);

void jmp_handler(re_list_t *instnode);

//void jcc_handler(re_list_t *instnode);
void ja_handler(re_list_t *instnode);


void push_handler(re_list_t *instnode);

void pop_handler(re_list_t *instnode);

void pushregs_handler(re_list_t *instnode);

void popregs_handler(re_list_t *instnode);

void pushflags_handler(re_list_t *instnode);

void popflags_handler(re_list_t *instnode);

void enter_handler(re_list_t *instnode);

void leave_handler(re_list_t *instnode);


void test_handler(re_list_t *instnode);

void cmp_handler(re_list_t * instnode);


void mov_handler(re_list_t *instnode);

void lea_handler(re_list_t *instnode);

void movcc_handler(re_list_t *instnode);

void xchg_handler(re_list_t *instnode);

void bswap_handler(re_list_t *instnode);

void xchgcc_handler(re_list_t *instnode);


void strcmp_handler(re_list_t *instnode);

void strload_handler(re_list_t *instnode);

void lods_handler(re_list_t *instnode);

void strmov_handler(re_list_t *instnode);

void movs_handler(re_list_t *instnode);

void strstore_handler(re_list_t *instnode);

void stos_handler(re_list_t *instnode);

void translate_handler(re_list_t *instnode);


void bittest_handler(re_list_t *instnode);

void bitset_handler(re_list_t *instnode);

void bitclear_handler(re_list_t *instnode);


void clear_dir_handler(re_list_t *instnode);


void int_handler(re_list_t *instnode);


void sys_handler(re_list_t *instnode);

void halt_handler(re_list_t *instnode);

void in_handler(re_list_t *instnode);

void out_handler(re_list_t *instnode);

void sysenter_handler(re_list_t *instnode);

void rdtsc_handler(re_list_t *instnode);

void cpuid_handler(re_list_t *instnode);


void nop_handler(re_list_t *instnode);

void szconv_handler(re_list_t *instnode);

void unknown_handler(re_list_t * instnode);

void pxor_handler(re_list_t* instnode);

void movdqu_handler(re_list_t* instnode);

void pmovmskb_hanlder(re_list_t* instnode);

void pcmpeqb_handler(re_list_t* instnode);

void pminub_handler(re_list_t* instnode);

void movaps_handler(re_list_t* instnode);

void movdqa_handler(re_list_t* instnode);

void movq_handler(re_list_t* instnode);

void pshufd_handler(re_list_t* instnode);

void punpcklbw_handler(re_list_t* instnode);

void ptest_handler(re_list_t* instnode);


//instruction resolver
void add_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void sub_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void mul_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void div_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void inc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void dec_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void shl_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void shr_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void rol_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void ror_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void and_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void or_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void xor_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void not_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void neg_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void call_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void callcc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void return_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void jmp_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

//void jcc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);
void ja_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void push_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pop_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pushregs_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void popregs_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pushflags_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void popflags_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void enter_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void leave_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void test_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void cmp_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void mov_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void lea_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void movzx_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist);

void movsx_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist);

void movcc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void xchg_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void bswap_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void xchgcc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void strcmp_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void strload_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void lods_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void strmov_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void movs_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void strstore_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void stos_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void translate_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void bittest_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void bitset_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void bitclear_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void clear_dir_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void int_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void sys_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void halt_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void in_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void out_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void sysenter_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void rdtsc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void cpuid_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


void nop_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void szconv_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void unknown_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pxor_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void movdqu_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pmovmskb_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pcmpeqb_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pminub_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void movaps_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void movdqa_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void movq_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void pshufd_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist);

void punpcklbw_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist);

void movlpd_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);

void ptest_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist);


// post heuristics functions
void mov_post_heuristics(re_list_t* instnode, re_list_t *instlist, re_list_t *uselist, re_list_t *deflist);

void pxor_post_heuristics(re_list_t* instnode, re_list_t *instlist, re_list_t *uselist, re_list_t *deflist);



//heuristic functions for instructions (post resolution)
int jmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //0

int jcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //1

int call_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //2

int callcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //3

int return_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //4

int add_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //5

int sub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //6

int mul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //7

int div_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //8

int inc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //9

int dec_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //10

int shl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //11

int shr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //12

int rol_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //13

int ror_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //14

int and_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //15

int or_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //16

int xor_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //17

int not_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //18

int neg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //19

int push_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //20

int pop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //21

int pushregs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //22

int popregs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //23

int pushflags_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //24

int popflags_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //25

int enter_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //26

int leave_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //27

int test_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //28

int cmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //29

int mov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //30

int movcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //31

int xchg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //32

int xchgcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //33

int strcmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //34

int strload_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //35

int strmov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //36

int strstore_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //37

int translate_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //38

int bittest_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //39

int bitset_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //40

int bitclear_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //41

int nop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //42

int szconv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //43

int unknown_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //44

int clear_dir_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //45

int sys_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //46

int int_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //47

int in_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //48

int out_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //49

int cpuid_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist); //49

#endif
