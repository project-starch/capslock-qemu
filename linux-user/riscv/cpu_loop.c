/*
 *  qemu user cpu loop
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu.h"
#include "user-internals.h"
#include "cpu_loop-common.h"
#include "signal-common.h"
#include "elf.h"
#include "semihosting/common-semi.h"

extern unsigned long guest_stack_size;
void helper_csdebuggencap(CPURISCVState *env, uint32_t rd, uint64_t rs1_v, uint64_t rs2_v);

void cpu_loop(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    int trapnr;
    target_ulong ret;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        case RISCV_EXCP_U_ECALL:
            env->pc += 4;
            if (env->gpr[xA7].val.scalar == TARGET_NR_arch_specific_syscall + 15) {
                /* riscv_flush_icache_syscall is a no-op in QEMU as
                   self-modifying code is automatically detected */
                ret = 0;
            } else {
                ret = do_syscall(env,
                                 env->gpr[(env->elf_flags & EF_RISCV_RVE)
                                    ? xT0 : xA7].val.scalar,
                                 env->gpr[xA0].val.scalar,
                                 env->gpr[xA1].val.scalar,
                                 env->gpr[xA2].val.scalar,
                                 env->gpr[xA3].val.scalar,
                                 env->gpr[xA4].val.scalar,
                                 env->gpr[xA5].val.scalar,
                                 0, 0);
            }
            if (ret == -QEMU_ERESTARTSYS) {
                env->pc -= 4;
            } else if (ret != -QEMU_ESIGRETURN) {
                env->gpr[xA0].val.scalar = ret;
                env->gpr[xA0].tag = false;
            }
            if (cs->singlestep_enabled) {
                goto gdbstep;
            }
            break;
        case RISCV_EXCP_ILLEGAL_INST:
            force_sig_fault(TARGET_SIGILL, TARGET_ILL_ILLOPC, env->pc);
            break;
        case RISCV_EXCP_BREAKPOINT:
        case EXCP_DEBUG:
        gdbstep:
            force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->pc);
            break;
        case RISCV_EXCP_SEMIHOST:
            do_common_semihosting(cs);
            env->pc += 4;
            break;
        default:
            // force_sig_fault(TARGET_SIGSEGV, TARGET_SEGV_MAPERR, env->pc);
            force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->pc);
            // EXCP_DUMP(env, "\nqemu: unhandled CPU exception %#x - aborting\n",
            //          trapnr);
            // exit(EXIT_FAILURE);
            break;
        }

        process_pending_signals(env);
    }
}

void target_cpu_copy_regs(CPUArchState *env, struct target_pt_regs *regs)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = cpu->opaque;
    struct image_info *info = ts->info;

    env->pc = regs->sepc;
    // helper_csdebuggencap(env, xSP, regs->sp - guest_stack_size, regs->sp);
    env->gpr[xSP].val.scalar = regs->sp;
    env->gpr[xSP].tag = false;
    // env->gpr[xSP].val.cap.bounds.cursor = regs->sp - 1024;
    env->elf_flags = info->elf_flags;

    if ((env->misa_ext & RVE) && !(env->elf_flags & EF_RISCV_RVE)) {
        error_report("Incompatible ELF: RVE cpu requires RVE ABI binary");
        exit(EXIT_FAILURE);
    }

    ts->stack_base = info->start_stack;
    ts->heap_base = info->brk;
    /* This will be filled in on the first SYS_HEAPINFO call.  */
    ts->heap_limit = 0;
}
