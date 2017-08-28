#include "insthandler.h"

void test_handler(re_list_t *instnode){
	cs_insn* inst;
	cs_x86_op *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval;

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	//dst = x86_get_dest_operand(inst);
	//src = x86_get_src_operand(inst);

	//	for debugginf use	
	print_all_operands(inst);
}


void cmp_handler(re_list_t *instnode){
	cs_insn* inst;
	cs_x86_op *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval;

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	//dst = x86_get_dest_operand(inst);
	//src = x86_get_src_operand(inst);

	//	for debugginf use	
	print_all_operands(inst);
}


void test_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

}


void cmp_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

}
