#ifndef __DISASSEMBLE__
#define __DISASSEMBLE__

#include <capstone/platform.h>
#include <capstone/capstone.h>

typedef struct platform {
	cs_arch arch;
	cs_mode mode;
	char *comment;
	cs_opt_type opt_type;
	cs_opt_value opt_value;
} re_platform_t;

bool disasm_one_inst(char *buf, size_t buf_size, int pos, cs_insn *inst);
#endif
