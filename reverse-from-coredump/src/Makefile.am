bin_PROGRAMS = reverse

#AM_CFLAGS= -DDEBUG -DLOG_INSTRUCTIONS -I ../include
AM_CFLAGS= -DBIN_ALIAS -DDEBUG -DFIX_OPTM -I ../include

reverse_CPPFLAGS = -msse4.1

handlers_FILES = handler_arithmetic.c handler_bit_manip.c handler_comparison.c handler_controlflow.c handler_logic.c handler_move.c handler_other.c handler_sse.c handler_stack.c handler_string.c handler_system.c handler_flag_manip.c handler_interrupt.c

reverse_SOURCES = reverse_execution.c global.c process_core.c process_binary.c access_memory.c common.c process_inst_data.c process_thread.c disassemble.c

#reverse_log.c solver.c alias_manager.c heuristics.c inst_handle_resolve.c re_dsmanager.c re_insttable.c re_mem_alias.c re_opdvalue.c analyze_result.c reverse_instructions.c bin_alias.c
