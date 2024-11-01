#ifndef RISCV_TARGET_CPU_H
#define RISCV_TARGET_CPU_H

static inline void cpu_clone_regs_child(CPURISCVState *env, target_ulong newsp,
                                        unsigned flags)
{
    if (newsp) {
        env->gpr[xSP].val.scalar = newsp;
        env->gpr[xSP].tag = false;
    }

    env->gpr[xA0].val.scalar = 0;
    env->gpr[xA0].tag = false;
}

static inline void cpu_clone_regs_parent(CPURISCVState *env, unsigned flags)
{
}

static inline void cpu_set_tls(CPURISCVState *env, target_ulong newtls)
{
    env->gpr[xTP].val.scalar = newtls;
    env->gpr[xTP].tag = false;
}

static inline abi_ulong get_sp_from_cpustate(CPURISCVState *state)
{
   return state->gpr[xSP].val.scalar;
}
#endif
