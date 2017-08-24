#ifndef __ELF_CORE__
#define __ELF_CORE__

#include <sys/procfs.h>
#include <gelf.h>
#include <libelf.h>
#include <elf.h>
#include <sys/reg.h>

#include "common.h"

typedef struct nt_thread_context_struct{
	long xmm_reg[32];
}nt_thread_context;

typedef struct nt_lts_info_struct{
	// note architecture
	Elf32_Word index;
	Elf32_Addr base;
	Elf32_Word length;
	Elf32_Word flag;
}nt_lts_info;

typedef struct nt_lts_struct{
	size_t nt_lts_num;
	nt_lts_info *lts_info;
}nt_lts;

typedef struct nt_file_info_struct{
	// note architecture
	Elf32_Addr start, end, pos;
	char name[FILE_NAME_SIZE];
}nt_file_info;

typedef struct nt_file_struct{
	size_t nt_file_num;
	nt_file_info *file_info;
}core_nt_file_info;

typedef struct thread_info_struct{
	size_t crash_thread;
	size_t thread_num;
	struct elf_prstatus *threads_status;
	nt_lts* lts;
	nt_thread_context *threads_context;
}core_thread_info;

typedef struct process_info_struct{
	int exist;
	struct elf_prpsinfo process_info;
}core_process_info;

typedef struct note_info_struct{
	core_nt_file_info core_file;
	core_process_info core_process;
	core_thread_info  core_thread;
}core_note_info;

typedef struct core_info_struct{
	size_t phdr_num;
	GElf_Phdr *phdr;
	core_note_info *note_info;
} elf_core_info;


int destroy_core_info(elf_core_info *coreinfo);

elf_core_info *parse_core(char *path);

int process_segment(Elf *elf, elf_core_info *coreinfo);

int process_note_segment(Elf *elf, elf_core_info *coreinfo);

void print_elf_type(Elf_Kind ek);

#endif
