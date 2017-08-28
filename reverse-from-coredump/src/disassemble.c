#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <capstone/capstone.h>

#include "reverse_log.h"
#include "disassemble.h"

// note architecture
re_platform_t platform = {
	CS_ARCH_X86,
	CS_MODE_32,
	"X86 32bit (ATT syntax)"
};

csh handle;

// modified from capstone demo examples
static void print_string_hex(char *comment, unsigned char *str, size_t len);
static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins);

// 0 if every malloc successes, -1 if any malloc encounters error
static int x86_copy_inst_info(cs_insn *dest, cs_insn *src) {
	memcpy(dest, src, sizeof(cs_insn));
	
	if ((dest->detail = (cs_detail *)malloc(sizeof(cs_detail))) == NULL) {
		LOG(stderr, "ERROR: Malloc Error\n");
		return -1;
	}

	memcpy(dest->detail, src->detail, sizeof(cs_detail));
	return 0;
}

// user-provided memory space for cs_insn
bool disasm_one_inst(char *buf, size_t buf_size, int pos, cs_insn *inst){
	cs_insn *insn;
	size_t count;
	int retval;

	cs_err err = cs_open(platform.arch, platform.mode, &handle);

	if (platform.opt_type)
		cs_option(handle, platform.opt_type, platform.opt_value);

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, buf, buf_size, pos, 0, &insn);

	if (count) {
		//LOG(stdout, "0x%" PRIx32 ":\t%s\t%s\n",
		//    (unsigned int)RE_X86_INST_TYPE(*inst),
		//    RE_X86_INST_MNEMONIC(*inst),
		//    RE_X86_INST_OP_STR(*inst));
		//print_insn_detail(handle, platform.mode, inst);
		x86_copy_inst_info(inst, insn);
		cs_free(insn, count);
	} else {
		LOG(stdout, "****************\n");
		LOG(stdout, "Platform: %s\n", platform.comment);
		print_string_hex("Code:", buf, buf_size);
		LOG(stderr, "ERROR: Failed to disasm given code!\n");
	}
	return (count != 0);
}

static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
	int count, i;
	cs_x86 *x86;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	x86 = &(ins->detail->x86);

	print_string_hex("\tPrefix:", x86->prefix, 4);

	print_string_hex("\tOpcode:", x86->opcode, 4);

	LOG(stdout, "\trex: 0x%x\n", x86->rex);

	LOG(stdout, "\taddr_size: %u\n", x86->addr_size);
	LOG(stdout, "\tmodrm: 0x%x\n", x86->modrm);
	LOG(stdout, "\tdisp: 0x%x\n", x86->disp);

	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		LOG(stdout, "\tsib: 0x%x\n", x86->sib);
		if (x86->sib_base != X86_REG_INVALID)
			LOG(stdout, "\t\tsib_base: %s\n", cs_reg_name(ud, x86->sib_base));
		if (x86->sib_index != X86_REG_INVALID)
			LOG(stdout, "\t\tsib_index: %s\n", cs_reg_name(ud, x86->sib_index));
		if (x86->sib_scale != 0)
			LOG(stdout, "\t\tsib_scale: %d\n", x86->sib_scale);
	}

	// SSE code condition
	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		LOG(stdout, "\tsse_cc: %u\n", x86->sse_cc);
	}

	// AVX code condition
	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		LOG(stdout, "\tavx_cc: %u\n", x86->avx_cc);
	}

	// AVX Suppress All Exception
	if (x86->avx_sae) {
		LOG(stdout, "\tavx_sae: %u\n", x86->avx_sae);
	}

	// AVX Rounding Mode
	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		LOG(stdout, "\tavx_rm: %u\n", x86->avx_rm);
	}

	count = cs_op_count(ud, ins, X86_OP_IMM);
	if (count) {
		LOG(stdout, "\timm_count: %u\n", count);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(ud, ins, X86_OP_IMM, i);
			LOG(stdout, "\t\timms[%u]: 0x%" PRIx64 "\n", i, x86->operands[index].imm);
		}
	}

	if (x86->op_count)
		LOG(stdout, "\top_count: %u\n", x86->op_count);
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch (op->access) {
			case CS_AC_READ:
				LOG(stdout, "\t\toperands[%u].access : Read\n", i);
				break;
			case CS_AC_WRITE:
				LOG(stdout, "\t\toperands[%u].access : Write\n", i);
				break;
		}

		switch((int)op->type) {
			case X86_OP_REG:
				LOG(stdout, "\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(ud, op->reg));
				break;
			case X86_OP_IMM:
				LOG(stdout, "\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_MEM:
				LOG(stdout, "\t\toperands[%u].type: MEM\n", i);
				if (op->mem.segment != X86_REG_INVALID)
					LOG(stdout, "\t\t\toperands[%u].mem.segment: REG = %s\n", i, cs_reg_name(ud, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					LOG(stdout, "\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(ud, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					LOG(stdout, "\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(ud, op->mem.index));
				if (op->mem.scale != 1)
					LOG(stdout, "\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					LOG(stdout, "\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
				break;
			default:
				break;
		}

		// AVX broadcast type
		if (op->avx_bcast != X86_AVX_BCAST_INVALID)
			LOG(stdout, "\t\toperands[%u].avx_bcast: %u\n", i, op->avx_bcast);

		// AVX zero opmask {z}
		if (op->avx_zero_opmask != false)
			LOG(stdout, "\t\toperands[%u].avx_zero_opmask: TRUE\n", i);

		LOG(stdout, "\t\toperands[%u].size: %u\n", i, op->size);
	}

	LOG(stdout, "\n");
}

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
        unsigned char *c;

        LOG(stdout, "%s", comment);
        for (c = str; c < str + len; c++) {
                LOG(stdout, "0x%02x ", *c & 0xff);
        }

        LOG(stdout, "\n");
}
