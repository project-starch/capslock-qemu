/*
 * RISC-V Emulation Helpers for QEMU.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 * Copyright (c) 2022      VRULL GmbH
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "capstone_defs.h"
#include "cap_mem_map.h"
#include "cap_rev_tree.h"
#include "trace.h"

/* Exceptions processing helpers */
G_NORETURN void riscv_raise_exception(CPURISCVState *env,
                                      uint32_t exception, uintptr_t pc)
{
    CPUState *cs = env_cpu(env);
    cs->exception_index = exception;
    cpu_loop_exit_restore(cs, pc);
}

void helper_raise_exception(CPURISCVState *env, uint32_t exception)
{
    riscv_raise_exception(env, exception, 0);
}

// #define CAPSTONE_EXCP_IS_BREAKPOINT

inline static void riscv_raise_exception_bp(CPURISCVState *env, RISCVException excp, uintptr_t pc) {
    #ifdef CAPSTONE_EXCP_IS_BREAKPOINT
        riscv_raise_exception(env, RISCV_EXCP_BREAKPOINT, pc);
    #else
        riscv_raise_exception(env, excp, pc);
    #endif
}

target_ulong helper_csrr(CPURISCVState *env, int csr)
{
    /*
     * The seed CSR must be accessed with a read-write instruction. A
     * read-only instruction such as CSRRS/CSRRC with rs1=x0 or CSRRSI/
     * CSRRCI with uimm=0 will raise an illegal instruction exception.
     */
    if (csr == CSR_SEED) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong val = 0;
    RISCVException ret = riscv_csrrw(env, csr, &val, 0, 0);

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }
    return val;
}

void helper_csrw(CPURISCVState *env, int csr, target_ulong src)
{
    target_ulong mask = env->xl == MXL_RV32 ? UINT32_MAX : (target_ulong)-1;
    RISCVException ret = riscv_csrrw(env, csr, NULL, src, mask);

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }
}

target_ulong helper_csrrw(CPURISCVState *env, int csr,
                          target_ulong src, target_ulong write_mask)
{
    target_ulong val = 0;
    RISCVException ret = riscv_csrrw(env, csr, &val, src, write_mask);

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }
    return val;
}

target_ulong helper_csrr_i128(CPURISCVState *env, int csr)
{
    Int128 rv = int128_zero();
    RISCVException ret = riscv_csrrw_i128(env, csr, &rv,
                                          int128_zero(),
                                          int128_zero());

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }

    env->retxh = int128_gethi(rv);
    return int128_getlo(rv);
}

void helper_csrw_i128(CPURISCVState *env, int csr,
                      target_ulong srcl, target_ulong srch)
{
    RISCVException ret = riscv_csrrw_i128(env, csr, NULL,
                                          int128_make128(srcl, srch),
                                          UINT128_MAX);

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }
}

target_ulong helper_csrrw_i128(CPURISCVState *env, int csr,
                       target_ulong srcl, target_ulong srch,
                       target_ulong maskl, target_ulong maskh)
{
    Int128 rv = int128_zero();
    RISCVException ret = riscv_csrrw_i128(env, csr, &rv,
                                          int128_make128(srcl, srch),
                                          int128_make128(maskl, maskh));

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }

    env->retxh = int128_gethi(rv);
    return int128_getlo(rv);
}


/*
 * check_zicbo_envcfg
 *
 * Raise virtual exceptions and illegal instruction exceptions for
 * Zicbo[mz] instructions based on the settings of [mhs]envcfg as
 * specified in section 2.5.1 of the CMO specification.
 */
static void check_zicbo_envcfg(CPURISCVState *env, target_ulong envbits,
                                uintptr_t ra)
{
#ifndef CONFIG_USER_ONLY
    if ((env->priv < PRV_M) && !get_field(env->menvcfg, envbits)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, ra);
    }

    if (env->virt_enabled &&
        (((env->priv <= PRV_S) && !get_field(env->henvcfg, envbits)) ||
         ((env->priv < PRV_S) && !get_field(env->senvcfg, envbits)))) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, ra);
    }

    if ((env->priv < PRV_S) && !get_field(env->senvcfg, envbits)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, ra);
    }
#endif
}

void helper_cbo_zero(CPURISCVState *env, target_ulong address)
{
    RISCVCPU *cpu = env_archcpu(env);
    uint16_t cbozlen = cpu->cfg.cboz_blocksize;
    int mmu_idx = cpu_mmu_index(env, false);
    uintptr_t ra = GETPC();
    void *mem;

    check_zicbo_envcfg(env, MENVCFG_CBZE, ra);

    /* Mask off low-bits to align-down to the cache-block. */
    address &= ~(cbozlen - 1);

    /*
     * cbo.zero requires MMU_DATA_STORE access. Do a probe_write()
     * to raise any exceptions, including PMP.
     */
    mem = probe_write(env, address, cbozlen, mmu_idx, ra);

    if (likely(mem)) {
        memset(mem, 0, cbozlen);
    } else {
        /*
         * This means that we're dealing with an I/O page. Section 4.2
         * of cmobase v1.0.1 says:
         *
         * "Cache-block zero instructions store zeros independently
         * of whether data from the underlying memory locations are
         * cacheable."
         *
         * Write zeros in address + cbozlen regardless of not being
         * a RAM page.
         */
        for (int i = 0; i < cbozlen; i++) {
            cpu_stb_mmuidx_ra(env, address + i, 0, mmu_idx, ra);
        }
    }
}

/*
 * check_zicbom_access
 *
 * Check access permissions (LOAD, STORE or FETCH as specified in
 * section 2.5.2 of the CMO specification) for Zicbom, raising
 * either store page-fault (non-virtualized) or store guest-page
 * fault (virtualized).
 */
static void check_zicbom_access(CPURISCVState *env,
                                target_ulong address,
                                uintptr_t ra)
{
    RISCVCPU *cpu = env_archcpu(env);
    int mmu_idx = cpu_mmu_index(env, false);
    uint16_t cbomlen = cpu->cfg.cbom_blocksize;
    void *phost;
    int ret;

    /* Mask off low-bits to align-down to the cache-block. */
    address &= ~(cbomlen - 1);

    /*
     * Section 2.5.2 of cmobase v1.0.1:
     *
     * "A cache-block management instruction is permitted to
     * access the specified cache block whenever a load instruction
     * or store instruction is permitted to access the corresponding
     * physical addresses. If neither a load instruction nor store
     * instruction is permitted to access the physical addresses,
     * but an instruction fetch is permitted to access the physical
     * addresses, whether a cache-block management instruction is
     * permitted to access the cache block is UNSPECIFIED."
     */
    ret = probe_access_flags(env, address, cbomlen, MMU_DATA_LOAD,
                             mmu_idx, true, &phost, ra);
    if (ret != TLB_INVALID_MASK) {
        /* Success: readable */
        return;
    }

    /*
     * Since not readable, must be writable. On failure, store
     * fault/store guest amo fault will be raised by
     * riscv_cpu_tlb_fill(). PMP exceptions will be caught
     * there as well.
     */
    probe_write(env, address, cbomlen, mmu_idx, ra);
}

void helper_cbo_clean_flush(CPURISCVState *env, target_ulong address)
{
    uintptr_t ra = GETPC();
    check_zicbo_envcfg(env, MENVCFG_CBCFE, ra);
    check_zicbom_access(env, address, ra);

    /* We don't emulate the cache-hierarchy, so we're done. */
}

void helper_cbo_inval(CPURISCVState *env, target_ulong address)
{
    uintptr_t ra = GETPC();
    check_zicbo_envcfg(env, MENVCFG_CBIE, ra);
    check_zicbom_access(env, address, ra);

    /* We don't emulate the cache-hierarchy, so we're done. */
}

#ifndef CONFIG_USER_ONLY

target_ulong helper_sret(CPURISCVState *env)
{
    uint64_t mstatus;
    target_ulong prev_priv, prev_virt;

    if (!(env->priv >= PRV_S)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong retpc = env->sepc;
    if (!riscv_has_ext(env, RVC) && (retpc & 0x3)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, GETPC());
    }

    if (get_field(env->mstatus, MSTATUS_TSR) && !(env->priv >= PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    if (env->virt_enabled && get_field(env->hstatus, HSTATUS_VTSR)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    }

    mstatus = env->mstatus;
    prev_priv = get_field(mstatus, MSTATUS_SPP);
    mstatus = set_field(mstatus, MSTATUS_SIE,
                        get_field(mstatus, MSTATUS_SPIE));
    mstatus = set_field(mstatus, MSTATUS_SPIE, 1);
    mstatus = set_field(mstatus, MSTATUS_SPP, PRV_U);
    if (env->priv_ver >= PRIV_VERSION_1_12_0) {
        mstatus = set_field(mstatus, MSTATUS_MPRV, 0);
    }
    env->mstatus = mstatus;

    if (riscv_has_ext(env, RVH) && !env->virt_enabled) {
        /* We support Hypervisor extensions and virtulisation is disabled */
        target_ulong hstatus = env->hstatus;

        prev_virt = get_field(hstatus, HSTATUS_SPV);

        hstatus = set_field(hstatus, HSTATUS_SPV, 0);

        env->hstatus = hstatus;

        if (prev_virt) {
            riscv_cpu_swap_hypervisor_regs(env);
        }

        riscv_cpu_set_virt_enabled(env, prev_virt);
    }

    riscv_cpu_set_mode(env, prev_priv);

    return retpc;
}

target_ulong helper_mret(CPURISCVState *env)
{
    if (!(env->priv >= PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong retpc = env->cap_mem ? env->cepc.val.scalar : env->mepc;
    if (!riscv_has_ext(env, RVC) && (retpc & 0x3)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, GETPC());
    }

    uint64_t mstatus = env->mstatus;
    target_ulong prev_priv = get_field(mstatus, MSTATUS_MPP);

    if (riscv_cpu_cfg(env)->pmp &&
        !pmp_get_num_rules(env) && (prev_priv != PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ACCESS_FAULT, GETPC());
    }

    target_ulong prev_virt = get_field(env->mstatus, MSTATUS_MPV) &&
                             (prev_priv != PRV_M);
    mstatus = set_field(mstatus, MSTATUS_MIE,
                        get_field(mstatus, MSTATUS_MPIE));
    mstatus = set_field(mstatus, MSTATUS_MPIE, 1);
    mstatus = set_field(mstatus, MSTATUS_MPP,
                        riscv_has_ext(env, RVU) ? PRV_U : PRV_M);
    mstatus = set_field(mstatus, MSTATUS_MPV, 0);
    if ((env->priv_ver >= PRIV_VERSION_1_12_0) && (prev_priv != PRV_M)) {
        mstatus = set_field(mstatus, MSTATUS_MPRV, 0);
    }
    if (env->cap_mem && prev_priv != PRV_M && !env->ctvec.tag) {
        uint64_t ctvec_addr = env->ctvec.val.scalar;
        env->ctvec.val.cap = env->pc_cap;
        env->ctvec.val.cap.cursor = ctvec_addr;
        env->ctvec.tag = true;
    }
    env->mstatus = mstatus;
    riscv_cpu_set_mode(env, prev_priv);

    if (riscv_has_ext(env, RVH)) {
        if (prev_virt) {
            riscv_cpu_swap_hypervisor_regs(env);
        }

        riscv_cpu_set_virt_enabled(env, prev_virt);
    }

    return retpc;
}

void helper_wfi(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    bool rvs = riscv_has_ext(env, RVS);
    bool prv_u = env->priv == PRV_U;
    bool prv_s = env->priv == PRV_S;

    if (((prv_s || (!rvs && prv_u)) && get_field(env->mstatus, MSTATUS_TW)) ||
        (rvs && prv_u && !env->virt_enabled)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    } else if (env->virt_enabled &&
               (prv_u || (prv_s && get_field(env->hstatus, HSTATUS_VTW)))) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    } else {
        // FIXME: the CPU is somehow never waken up with these
        // NOP is a legal implementation of WFI
        // cs->halted = 1;
        // cs->exception_index = EXCP_HLT;
        cpu_loop_exit(cs);
    }
}

void helper_tlb_flush(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    if (!env->virt_enabled &&
        (env->priv == PRV_U ||
         (env->priv == PRV_S && get_field(env->mstatus, MSTATUS_TVM)))) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    } else if (env->virt_enabled &&
               (env->priv == PRV_U || get_field(env->hstatus, HSTATUS_VTVM))) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    } else {
        tlb_flush(cs);
    }
}

void helper_tlb_flush_all(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    tlb_flush_all_cpus_synced(cs);
}

void helper_hyp_tlb_flush(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);

    if (env->virt_enabled) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    }

    if (env->priv == PRV_M ||
        (env->priv == PRV_S && !env->virt_enabled)) {
        tlb_flush(cs);
        return;
    }

    riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
}

void helper_hyp_gvma_tlb_flush(CPURISCVState *env)
{
    if (env->priv == PRV_S && !env->virt_enabled &&
        get_field(env->mstatus, MSTATUS_TVM)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    helper_hyp_tlb_flush(env);
}

static int check_access_hlsv(CPURISCVState *env, bool x, uintptr_t ra)
{
    if (env->priv == PRV_M) {
        /* always allowed */
    } else if (env->virt_enabled) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, ra);
    } else if (env->priv == PRV_U && !get_field(env->hstatus, HSTATUS_HU)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, ra);
    }

    int mode = get_field(env->hstatus, HSTATUS_SPVP);
    if (!x && mode == PRV_S && get_field(env->vsstatus, MSTATUS_SUM)) {
        mode = MMUIdx_S_SUM;
    }
    return mode | MMU_2STAGE_BIT;
}

target_ulong helper_hyp_hlv_bu(CPURISCVState *env, target_ulong addr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);

    return cpu_ldb_mmu(env, addr, oi, ra);
}

target_ulong helper_hyp_hlv_hu(CPURISCVState *env, target_ulong addr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUW, mmu_idx);

    return cpu_ldw_mmu(env, addr, oi, ra);
}

target_ulong helper_hyp_hlv_wu(CPURISCVState *env, target_ulong addr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUL, mmu_idx);

    return cpu_ldl_mmu(env, addr, oi, ra);
}

target_ulong helper_hyp_hlv_d(CPURISCVState *env, target_ulong addr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUQ, mmu_idx);

    return cpu_ldq_mmu(env, addr, oi, ra);
}

void helper_hyp_hsv_b(CPURISCVState *env, target_ulong addr, target_ulong val)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);

    cpu_stb_mmu(env, addr, val, oi, ra);
}

void helper_hyp_hsv_h(CPURISCVState *env, target_ulong addr, target_ulong val)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUW, mmu_idx);

    cpu_stw_mmu(env, addr, val, oi, ra);
}

void helper_hyp_hsv_w(CPURISCVState *env, target_ulong addr, target_ulong val)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUL, mmu_idx);

    cpu_stl_mmu(env, addr, val, oi, ra);
}

void helper_hyp_hsv_d(CPURISCVState *env, target_ulong addr, target_ulong val)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, false, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUQ, mmu_idx);

    cpu_stq_mmu(env, addr, val, oi, ra);
}

/*
 * TODO: These implementations are not quite correct.  They perform the
 * access using execute permission just fine, but the final PMP check
 * is supposed to have read permission as well.  Without replicating
 * a fair fraction of cputlb.c, fixing this requires adding new mmu_idx
 * which would imply that exact check in tlb_fill.
 */
target_ulong helper_hyp_hlvx_hu(CPURISCVState *env, target_ulong addr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, true, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUW, mmu_idx);

    return cpu_ldw_code_mmu(env, addr, oi, GETPC());
}

target_ulong helper_hyp_hlvx_wu(CPURISCVState *env, target_ulong addr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = check_access_hlsv(env, true, ra);
    MemOpIdx oi = make_memop_idx(MO_TEUL, mmu_idx);

    return cpu_ldl_code_mmu(env, addr, oi, ra);
}

#endif /* !CONFIG_USER_ONLY */

/* Capstone helpers */

// void helper_csmovc(CPURISCVState *env, uint32_t rd, uint32_t rs1) {
//     capregval_t *rd_v = &env->gpr[rd];
//     capregval_t *rs1_v = &env->gpr[rs1];

//     if(rs1 != rd) {
//         *rd_v = *rs1_v;
//         if(rs1_v->tag && !captype_is_copyable(rs1_v->val.cap.type)) {
//             *rs1_v = CAPREGVAL_NULL;
//         }
//     }
// }

// void helper_cscincoffset(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
//     capregval_t *rd_v = &env->gpr[rd];
//     capregval_t *rs1_v = &env->gpr[rs1];
//     capregval_t *rs2_v = &env->gpr[rs2];

//     assert(rs1_v->tag && !rs2_v->tag);

//     assert(rs1_v->val.cap.type != CAP_TYPE_UNINIT &&
//            rs1_v->val.cap.type != CAP_TYPE_SEALED);

//     capaddr_t offset = rs2_v->val.scalar;

//     if(rs1 != rd) {
//         *rd_v = *rs1_v;
//         if(!captype_is_copyable(rs1_v->val.cap.type)) {
//             *rs1_v = CAPREGVAL_NULL;
//         }
//     }

//     rd_v->val.cap.cursor += offset;
// }

// void helper_cscincoffsetimm(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint64_t offset) {
//     capregval_t *rd_v = &env->gpr[rd];
//     capregval_t *rs1_v = &env->gpr[rs1];

//     assert(rs1_v->tag);

//     assert(rs1_v->val.cap.type != CAP_TYPE_UNINIT &&
//            rs1_v->val.cap.type != CAP_TYPE_SEALED);

//     if(rs1 != rd) {
//         *rd_v = *rs1_v;
//         if(!captype_is_copyable(rs1_v->val.cap.type)) {
//             *rs1_v = CAPREGVAL_NULL;
//         }
//     }

//     rd_v->val.cap.cursor += offset;
// }

void helper_csscc(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *rs2_v = &env->gpr[rs2];

    assert(rs1_v->tag && !rs2_v->tag);

    assert(rs1_v->val.cap.type != CAP_TYPE_UNINIT &&
           rs1_v->val.cap.type != CAP_TYPE_SEALED);

    capaddr_t cursor = rs2_v->val.scalar;

    if(rs1 != rd) {
        *rd_v = *rs1_v;
        if(!captype_is_copyable(rs1_v->val.cap.type)) {
            *rs1_v = CAPREGVAL_NULL;
        }
    }

    rd_v->val.cap.cursor = cursor;
}

void helper_cslcc(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t imm) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    bool check_passed = true;
    // we allow 2 (cursor) to be queried for scalar values too
    if (imm != 8 && imm != 2) {
        check_passed = check_passed && rs1_v->tag;
        // check_passed = check_passed && (imm != 2 || rs1_v->val.cap.type != CAP_TYPE_SEALED);
        check_passed = check_passed && (imm != 4 || (rs1_v->val.cap.type != CAP_TYPE_SEALED && rs1_v->val.cap.type != CAP_TYPE_SEALEDRET));
        check_passed = check_passed && (imm != 5 || (rs1_v->val.cap.type != CAP_TYPE_SEALED && rs1_v->val.cap.type != CAP_TYPE_SEALEDRET));
        check_passed = check_passed && (imm != 6 || rs1_v->val.cap.type == CAP_TYPE_SEALED || rs1_v->val.cap.type == CAP_TYPE_SEALEDRET);
        check_passed = check_passed && (imm != 7 || rs1_v->val.cap.type == CAP_TYPE_SEALEDRET);
    }
    if (!check_passed) {
        CAPSTONE_DEBUG_PRINT("Invalid operands to lcc!\n");
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
        return;
    }
    switch(imm) {
        case 0:
            pthread_mutex_lock(&cr_tree_lock);
            capregval_set_scalar(rd_v, cap_rev_tree_check_valid(rs1_v->val.cap.bounds[0].rev_node) ? 1 : 0); // TODO: let's say it's always valid for now
            pthread_mutex_unlock(&cr_tree_lock);
            break;
        case 1:
            capregval_set_scalar(rd_v, (capaddr_t)rs1_v->val.cap.type);
            break;
        case 2:
            capregval_set_scalar(rd_v, rs1_v->val.cap.cursor);
            break;
        case 3:
            capregval_set_scalar(rd_v, rs1_v->val.cap.bounds[0].base);
            break;
        case 4:
            capregval_set_scalar(rd_v, rs1_v->val.cap.bounds[0].end);
            break;
        case 5:
            capregval_set_scalar(rd_v, (capaddr_t)rs1_v->val.cap.perms);
            break;
        case 6:
            capregval_set_scalar(rd_v, (capaddr_t)rs1_v->val.cap.async);
            break;
        case 7:
            capregval_set_scalar(rd_v, (capaddr_t)rs1_v->val.cap.reg);
            break;
        case 8:
            capregval_set_scalar(rd_v, rs1_v->tag ? 1 : 0);
            break;
        default:
            capregval_set_scalar(rd_v, 0);
    }
}

static void drop_impl(CPURISCVState *env, capregval_t *rv, bool is_stack) {
    // fprintf(stderr, "Dropping %lx\n", rv->val.scalar);
    if (rv->tag) {
        pthread_mutex_lock(&cr_tree_lock);
        bool is_far_oob;
        bool found = cap_bounds_collapse(&cr_tree, rv->val.cap.bounds, rv->val.scalar, 1, &is_far_oob);
        // if (found) {
        //     fprintf(stderr, "Found ");
        //     if (cap_rev_tree_check_valid(rv->val.cap.bounds[0].rev_node)) {
        //         fprintf(stderr, "Valid %d\n", is_far_oob);
        //     } else {
        //         fprintf(stderr, "Invalid %d\n", is_far_oob);
        //     }
        // }
        // fprintf(stderr, "Dropping\n");
        if (found && cap_rev_tree_check_valid(rv->val.cap.bounds[0].rev_node)) {
            // find the root of the tree which is the owner of the allocation
            cap_rev_node_t *root;
            for(root = rv->val.cap.bounds[0].rev_node; root->parent != NULL; root = root->parent);
            // if (!is_stack) {
            //     if (root->range.base != rv->val.scalar) {
            //         CAPSTONE_DEBUG_PRINT("Attempting to drop an invalid capability (invalid address) %lx %lx!\n",
            //             root->range.base,
            //             rv->val.scalar);
            //         riscv_raise_exception(env, RISCV_EXCP_INVALID_CAP, GETPC());
            //     }
            // }
            // cap_rev_node_t *node =
            //     rv->val.cap.bounds[0].rev_node;
            // fprintf(stderr, "Dropping %lx %p %lx %lx -- %p %lx %lx in %d @ %lx\n",
            //     rv->val.scalar,
            //     node, node->range.base, node->range.end,
            //     root, root->range.base, root->range.end, getpid(), env->pc);
            cap_rev_tree_revoke(&cr_tree, root);
        } else if (!is_far_oob) {
            // FIXME: add a separate one with checks for heap double free
            CAPSTONE_DEBUG_PRINT("Attempting to drop an invalid capability! %lx %p in %d @ %lx\n", rv->val.scalar, rv->val.cap.bounds[0].rev_node, getpid(), env->pc);
            riscv_raise_exception(env, RISCV_EXCP_INVALID_CAP, GETPC());
        } else
            rv->tag = false;
        pthread_mutex_unlock(&cr_tree_lock);
    }
}

void helper_csrevoke(CPURISCVState *env, uint32_t rs1) {
    assert(false && "Not supposed to be used");
    capregval_t *rs1_v = &env->gpr[rs1];

    assert(rs1_v->tag);

    pthread_mutex_lock(&cr_tree_lock);
    bool bounds_found = cap_bounds_collapse(&cr_tree, rs1_v->val.cap.bounds, rs1_v->val.cap.cursor, 1, NULL);

    if(bounds_found) {
        cap_rev_tree_revoke(&cr_tree, rs1_v->val.cap.bounds[0].rev_node);
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

static void borrow_impl(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2, bool mutable) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *rs2_v = &env->gpr[rs2]; // length

    // for borrowing, we merely make sure there's no mutable capabilities from now on
    // regardless of whether this is a mutable or immutable borrow

    if (!rs1_v->tag) {
        *rd_v = *rs1_v;
        return;
    }

    pthread_mutex_lock(&cr_tree_lock);
    bool bounds_found = cap_bounds_collapse(&cr_tree, rs1_v->val.cap.bounds, rs1_v->val.cap.cursor, 1, NULL);

    // FIXME: not handling interior mutability correctly
    if(bounds_found) {
        // cap_rev_tree_revoke(&cr_tree, rs1_v->val.cap.bounds[0].rev_node, false);
        // no revocation is needed now, delayed to access time

        if(!cap_rev_tree_check_valid(rs1_v->val.cap.bounds[0].rev_node)) {
            CAPSTONE_DEBUG_PRINT("Attempting to borrow from an invalid capability (node = %p) @ pc = %lx!\n",
                rs1_v->val.cap.bounds[0].rev_node,
                env->pc);
            for(cap_rev_node_t *node = rs1_v->val.cap.bounds[0].rev_node; node != NULL; node = node->parent) {
                fprintf(stderr, "> %p: %d %d %lx %lx\n", node, node->valid, node->ty,
                    node->range.base, node->range.end);
            }
            pthread_mutex_unlock(&cr_tree_lock);
            riscv_raise_exception_bp(env, RISCV_EXCP_INVALID_CAP, GETPC());
        }

        reg_overwrite(&cr_tree, rd_v);

        uintptr_t base = rs1_v->val.scalar;
        uintptr_t end;
        if (rs2_v->val.scalar == 0) {
            // foreign type, we don't know anything about it
            // just inherit
            end = rs1_v->val.cap.bounds[0].end;
        } else {
            end = rs1_v->val.scalar + rs2_v->val.scalar;
        }

        // FIXME: some how this assertion fails in some cases
        // assert(base >= rs1_v->val.cap.bounds[0].base && end <= rs1_v->val.cap.bounds[0].end);

        // fprintf(stderr, "Borrowing %lx %lx <- %lx %lx @ %lx\n", base, end, rs1_v->val.cap.bounds[0].base, rs1_v->val.cap.bounds[0].end,
        //     env->pc);

        cap_rev_node_t *from_node = rs1_v->val.cap.bounds[0].rev_node;
        if(rs1 != rd) {
            *rd_v = *rs1_v;
        }
        // if(mutable) {
        //     cap_rev_node_range_t range;
        //     range.base = rs1_v->val.cap.bounds[0].base;
        //     range.end = rs1_v->val.cap.bounds[0].end;
        //     fprintf(stderr, "Borrow %lx %lx %d\n", range.base, range.end, rs1_v->val.cap.bounds[0].rev_node->is_unsafecell);
        //     cap_rev_tree_access(&cr_tree, rs1_v->val.cap.bounds[0].rev_node, &range, true);
        // }
        // FIXME: mutable borrow should only turn existing overlapping caps into immutable ones
        // it is raw or ref
        for (int i = 1; i < CAP_MAX_PROVENANCE_N; i ++)
            rd_v->val.cap.bounds[i].rev_node = NULL;
        rd_v->val.cap.bounds[0].rev_node = cap_rev_tree_borrow(&cr_tree, from_node, mutable,
            base, end);
        // fprintf(stderr, "Borrow new node %p -> %p %lx %lx\n", from_node, rd_v->val.cap.bounds[0].rev_node, base, end);
        rd_v->val.cap.bounds[0].base = base;
        rd_v->val.cap.bounds[0].end = end;
    } else {
        rs1_v -> tag = false;
        *rd_v = *rs1_v;
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_csborrow(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    CAPSTONE_DEBUG_INFO("Borrow %u <- %u\n", rd, rs1);
    borrow_impl(env, rd, rs1, rs2, false);
}


void helper_csborrowmut(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    CAPSTONE_DEBUG_INFO("Borrowmut %u <- %u\n", rd, rs1);
    borrow_impl(env, rd, rs1, rs2, true);
}

void helper_csmarkunsafecell(CPURISCVState *env, uint32_t rs1, uint32_t rs2) {
    capregval_t *rs1_v = &env->gpr[rs1];
    cap_rev_node_type_t ty = (cap_rev_node_type_t)env->gpr[rs2].val.scalar;
    if (rs2 == 0)
        ty = CAP_REV_NODE_TYPE_REF;
    if(rs1_v->tag) {
        pthread_mutex_lock(&cr_tree_lock);
        if(cap_rev_tree_check_valid(rs1_v->val.cap.bounds[0].rev_node))
            cap_rev_tree_mark_unsafecell(&cr_tree, rs1_v->val.cap.bounds[0].rev_node, ty);
        pthread_mutex_unlock(&cr_tree_lock);
    }
}

void helper_csshrink(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    // TODO: use more TCG instructions for better performance
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *rs2_v = &env->gpr[rs2];

    if(rs1_v->tag) {
        capaddr_t base = rs1_v->val.scalar;
        cap_bounds_collapse(&cr_tree, rs1_v->val.cap.bounds, base, (capaddr_t)rs2_v->val.scalar, NULL);

        capaddr_t end;
        if (rs2_v->val.scalar == 0) {
            end = rs1_v->val.cap.bounds[0].end;
        } else {
            end = rs1_v->val.scalar + rs2_v->val.scalar;
        }
        // fprintf(stderr, "Shrink %lx %lx %lx %lx\n", base, end, rs1_v->val.cap.bounds[0].base, rs1_v->val.cap.bounds[0].end);
        assert(base <= end);
        // FIXME: some how this assertion fails in some cases
        // assert(
        //     !rs1_v->tag
        //     || (base >= rs1_v->val.cap.bounds[0].base && end <= rs1_v->val.cap.bounds[0].end)
        // );

        *rd_v = *rs1_v;
        rd_v->val.cap.bounds[0].base = base;
        rd_v->val.cap.bounds[0].end = end;

        if(rd_v->tag) {
            if(rd_v->val.cap.cursor < base) {
                rd_v->val.cap.cursor = base;
            } else if(rd_v->val.cap.cursor > end) {
                rd_v->val.cap.cursor = end;
            }
        }
    } else {
        *rd_v = *rs1_v;
    }
}

void helper_csshrinkto(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint64_t size) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    assert((int64_t)size >= 0);

    // assert(rs1_v->tag);
    // assert(rs1_v->val.cap.type == CAP_TYPE_LIN || rs1_v->val.cap.type == CAP_TYPE_NONLIN ||
    //        rs1_v->val.cap.type == CAP_TYPE_UNINIT);
    // fprintf(stderr, "Shrink to %lx %lx %lx %lx\n", rs1_v->val.cap.bounds[0].base,
    // rs1_v->val.cap.bounds[0].end, rs1_v->val.cap.cursor, size);
    // assert(!rs1_v->tag || (rs1_v->val.cap.cursor >= rs1_v->val.cap.bounds[0].base &&
    //         rs1_v->val.cap.cursor + size <= rs1_v->val.cap.bounds[0].end));

    reg_overwrite(&cr_tree, rd_v);
    // cap_rev_tree_update_refcount(&cr_tree, rs1_v->val.cap.bounds[0].rev_node, 1);
    *rd_v = *rs1_v;
    rd_v->val.cap.bounds[0].base = rd_v->val.cap.cursor;
    rd_v->val.cap.bounds[0].end = rd_v->val.cap.cursor + size;
}

void helper_cssplit(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    assert(false && "Unsupported!");
}

void helper_cstighten(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t perms) {
    assert(false && "Unsupported!");
}

void helper_csdrop(CPURISCVState *env, uint32_t rs1) {
    CAPSTONE_DEBUG_INFO("Dropping capability in %u\n", rs1);
    capregval_t *rs1_v = &env->gpr[rs1];

    drop_impl(env, rs1_v, false);
}


void helper_cssavesp(CPURISCVState *env, uint32_t rs1) {
    assert(env->sp_stack_n < SP_STACK_SIZE);
    env->sp_stack[env->sp_stack_n] = env->gpr[rs1];
    ++ env->sp_stack_n;
    // fprintf(stderr, "Push %lx %lx\n", env->gpr[rs1].val.cap.bounds[0].base, env->gpr[rs1].val.cap.bounds[0].end);
    if (env->gpr[rs1].tag) {
        pthread_mutex_lock(&cr_tree_lock);
        cap_rev_tree_update_refcount_cap(&env->gpr[rs1].val.cap, 1);
        pthread_mutex_unlock(&cr_tree_lock);
    }
}

void helper_csloadsp(CPURISCVState *env, uint32_t rd) {
    assert(env->sp_stack_n > 0);
    // fprintf(stderr, "Pop\n");
    -- env->sp_stack_n;
    env->gpr[rd] = env->sp_stack[env->sp_stack_n];
    if (env->sp_stack[env->sp_stack_n].tag) {
        pthread_mutex_lock(&cr_tree_lock);
        cap_rev_tree_update_refcount_cap(&env->sp_stack[env->sp_stack_n].val.cap, -1);
        pthread_mutex_unlock(&cr_tree_lock);
    }
}

void helper_csgetsp(CPURISCVState *env, uint32_t rd, uint64_t idx) {
    // pop the top of the stack below the current sp.
    // this is to support longjmp-like operations e.g., panic
    idx &= 0xfff;
    if(env->sp_stack_n <= idx) {
        fprintf(stderr, "Bad stack getsp before popping: %d %lu @ %lx\n", env->sp_stack_n, idx, env->pc);
        riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
        return;
    }
    uintptr_t sp = env->gpr[2].val.scalar;
    while (env->sp_stack_n > 0 && env->sp_stack[env->sp_stack_n - 1].val.scalar < sp) {
        drop_impl(env, &env->sp_stack[env->sp_stack_n - 1], true);
        helper_csloadsp(env, 0);
    }

    if(env->sp_stack_n <= idx) {
        fprintf(stderr, "Bad stack getsp: %d %lu @ %lx\n", env->sp_stack_n, idx, env->pc);
    }
    assert(env->sp_stack_n > idx);
    capregval_t *sp_v = &env->sp_stack[env->sp_stack_n - 1 - idx];
    // fprintf(stderr, "Get %u <- %lu = %lx %lx\n", rd, idx, sp_v->val.cap.bounds[0].base, sp_v->val.cap.bounds[0].end);
    env->gpr[rd] = *sp_v;
}

void helper_csseal(CPURISCVState *env, uint32_t rd, uint32_t rs1) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    if(!rs1_v->tag) {
        CAPSTONE_DEBUG_PRINT("Sealing requires a capability\n");
        riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
    }

    if(rs1_v->val.cap.type != CAP_TYPE_LIN) {
        CAPSTONE_DEBUG_PRINT("Sealing requires a linear capability\n");
        riscv_raise_exception(env, RISCV_EXCP_UNEXP_CAP_TYPE, GETPC());
    }

    if(!cap_perms_allow(rs1_v->val.cap.perms, CAP_PERMS_RW)) {
        CAPSTONE_DEBUG_PRINT("Sealing requires a RW capability\n");
        riscv_raise_exception(env, RISCV_EXCP_INSUF_CAP_PERMS, GETPC());
    }

    if(cap_size(&rs1_v->val.cap.bounds[0]) < CAP_SEALED_SIZE_MIN ||
       !cap_aligned(&rs1_v->val.cap.bounds[0], 4)) {
        CAPSTONE_DEBUG_PRINT("Sealing requires an aligned region of sufficient size\n");
    }

    reg_overwrite(&cr_tree, rd_v);
    *rd_v = *rs1_v;
    rd_v->val.cap.type = CAP_TYPE_SEALED;
    rd_v->val.cap.async = CAP_ASYNC_SYNC;

    if(rd != rs1) {
        *rs1_v = CAPREGVAL_NULL;
    }
}

void helper_csccsrrw(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint64_t ccsr_id) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *ccsr = NULL;
    capregval_t tmp;

    CPUState* cpu = env_cpu(env);

    // assert(rs1_v->tag);
    bool needs_tlb_flush = false;

    switch((capstone_ccsr_id_t)ccsr_id) {
        case CAPSTONE_CCSR_CTVEC:
            ccsr = &env->ctvec;
            break;
        case CAPSTONE_CCSR_CIH:
            assert(!env->cih.tag); /* only writable when originally not a capability */
            ccsr = &env->cih;
            break;
        case CAPSTONE_CCSR_CEPC:
            ccsr = &env->cepc;
            break;
        case CAPSTONE_CCSR_CSCRATCH:
            ccsr = &env->cscratch;
            break;
        default:
            if((ccsr_id & CAPSTONE_CCSR_CPMP_MASK) == CAPSTONE_CCSR_CPMP_PAT) {
                ccsr = &env->cpmp[ccsr_id & CAPSTONE_CCSR_CPMP_IND_MASK];
                needs_tlb_flush = true;
                break;
            }
            assert(false); // not a valid CCSR
    }

    tmp = *ccsr;
    *ccsr = *rs1_v;
    if(!captype_is_copyable(rs1_v->val.cap.type)) {
        *rs1_v = CAPREGVAL_NULL;
    }
    reg_overwrite(&cr_tree, rd_v);
    *rd_v = tmp;

    if(needs_tlb_flush) {
        tlb_flush(cpu);
    }
}

/* Capability-based memory access */

#define CAPSTONE_IMM12_SEXT(x) ((x) | (((-((x) >> 11)) << 12)))

inline static void print_bounds(capfat_t *cap) {
    for (int i = 0; i < CAP_MAX_PROVENANCE_N; i ++) {
        if (cap->bounds[i].rev_node != NULL) {
            CAPSTONE_DEBUG_PRINT("Bounds %d: %lx -- %lx (valid = %d, unsafecell = %d) @ %p\n", i, cap->bounds[i].base, cap->bounds[i].end,
                cap_rev_tree_check_valid(cap->bounds[i].rev_node), cap_rev_tree_is_unsafe_cell(cap->bounds[i].rev_node), cap->bounds[i].rev_node);
            CAPSTONE_DEBUG_PRINT("Parents unsafecell:\n");
            for(cap_rev_node_t *cur = cap->bounds[i].rev_node->parent; cur != NULL; cur = cur->parent) {
                CAPSTONE_DEBUG_PRINT("UnsafeCell = %d\n", cap_rev_tree_is_unsafe_cell(cur));
            }
        }
    }
}

static void _helper_access_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t rs2, uint32_t memop, bool is_store) {
    // CAPSTONE_DEBUG_PRINT("Cap mem access %u %lx\n", rs1, imm);

    capregval_t *rs1_v = &env->gpr[rs1];

    unsigned size = memop_size((MemOp)memop);

    if(rs1_v->tag) {
        capfat_t *cap = &rs1_v->val.cap;

        // fprintf(stderr, "Memacc (%s) with cap %u\n", is_store ? "store" : "load", cap->bounds[0].rev_node);
        // CAPSTONE_DEBUG_PRINT("Cap mem access addr = %lx, size = %lu\n", addr, (capaddr_t)size);
        // TODO: bounds check only for now
        // if(!cap_in_bounds(&cap->bounds, addr, (capaddr_t)size)) {
        //     CAPSTONE_DEBUG_PRINT("Cap mem access OOB: addr = %lx, size = %lu, bounds = (%lx, %lx) @ pc = %lx\n", addr, (capaddr_t)size,
        //         cap->bounds[0].base, cap->bounds[0].end, env->pc);
        //     RISCVException excp = is_store ? RISCV_EXCP_STORE_AMO_ACCESS_FAULT : RISCV_EXCP_LOAD_ACCESS_FAULT;
        //     riscv_raise_exception_bp(env, excp, GETPC());
        // }

        bool bounds_found, is_far_oob;
        pthread_mutex_lock(&cr_tree_lock);
        bounds_found = cap_bounds_collapse(&cr_tree, cap->bounds, addr, (capaddr_t)size, &is_far_oob);
        if (bounds_found) {
            if (is_store && !cap_rev_tree_check_valid(cap->bounds[0].rev_node)) {
                CAPSTONE_DEBUG_PRINT("Attempting to use invalid capability for store (address = %lx, size = %x, node = %p) @ pc = %lx!\n",
                    addr, size,
                    cap->bounds[0].rev_node,
                    env->pc);
                print_bounds(cap);
                pthread_mutex_unlock(&cr_tree_lock);
                riscv_raise_exception_bp(env, RISCV_EXCP_STORE_AMO_ACCESS_FAULT, GETPC());
            }

            if (!is_store && !cap_rev_tree_check_valid(cap->bounds[0].rev_node)) {
                CAPSTONE_DEBUG_PRINT("Attempting to use an invalid capability for load (address = %lx, size = %x, node = %p) @ pc = %lx!\n",
                    addr, size,
                    cap->bounds[0].rev_node,
                    env->pc);
                print_bounds(cap);
                pthread_mutex_unlock(&cr_tree_lock);
                riscv_raise_exception_bp(env, RISCV_EXCP_LOAD_ACCESS_FAULT, GETPC());
            }

            cap_rev_node_range_t range;
            // range.base = cap->bounds[0].base;
            // range.end = cap->bounds[0].end;
            range.base = addr;
            range.end = addr + size;
            assert(cap_rev_tree_access(&cr_tree, cap->bounds[0].rev_node, &range, is_store));
        } else if (!is_far_oob) {
            // If too far OOB, we don't consider it a violation (potentially bad provenance tracking)
            CAPSTONE_DEBUG_PRINT("Capability access OOB %lx size = %x @ pc = %lx\n", addr, size, env->pc);
            print_bounds(cap);

            pthread_mutex_unlock(&cr_tree_lock);
            RISCVException excp = is_store ? RISCV_EXCP_STORE_AMO_ACCESS_FAULT : RISCV_EXCP_LOAD_ACCESS_FAULT;
            riscv_raise_exception_bp(env, excp, GETPC());
        } else {
            env->gpr[rs1].tag = false;
        }
        pthread_mutex_unlock(&cr_tree_lock);
    }
    // else {
    //     CAPSTONE_DEBUG_PRINT("Cap mem access requires capability\n");
    //     riscv_raise_exception_bp(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
    // }


    if(size == 8) {
        // accessing capabilities in memory, extra checks needed
        // check alignment
        if(is_store) {
            if(env->gpr[rs2].tag) {
                CAPSTONE_DEBUG_INFO("Cap stored to 0x%lx from %u\n", addr, rs2);
            }
            if (env->gpr[rs2].tag && (addr & 7)) {
                CAPSTONE_DEBUG_PRINT("Unaligned cap access (addr = 0x%lx)\n", addr);
                riscv_raise_exception(env, RISCV_EXCP_STORE_AMO_ADDR_MIS, GETPC());
            }
        } else {
            uint64_t paddr = (uint64_t)capstone_get_haddr(env, (vaddr)addr, MMU_DATA_LOAD);
            pthread_mutex_lock(&cr_tree_lock);
            env->load_is_cap = cap_mem_map_query(&cm_map, paddr, NULL);
            pthread_mutex_unlock(&cr_tree_lock);
            if(env->load_is_cap) {
                CAPSTONE_DEBUG_INFO("Cap loaded from %lx (paddr = %lx, pc = %lx)\n", addr, paddr, env->pc);
                // fprintf(stderr, "Cap loaded from %lx (paddr = %lx, pc = %lx)\n", addr, paddr, env->pc);
            }
            if(env->load_is_cap && (addr & 7)) {
                CAPSTONE_DEBUG_PRINT("Unaligned cap access (addr = 0x%lx)\n", addr);
                riscv_raise_exception(env, RISCV_EXCP_LOAD_ADDR_MIS, GETPC());
            }
        }
    }

}

void helper_load_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t memop) {
    _helper_access_with_cap(env, addr, rs1, 0, memop, false);
}

void helper_cap_scrub(CPURISCVState *env, uint64_t addr) {
    uint64_t paddr = (uint64_t)capstone_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
    pthread_mutex_lock(&cr_tree_lock);
    cap_mem_map_remove(&cm_map, paddr);
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_store_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t rs2,
                        uint32_t memop, uint32_t use_cap) {
    // if (rs2 == 10 && lcced) {
    //     CAPSTONE_DEBUG_PRINT("x10 stored to 0x%lx\n", addr);
    // }
    // if (env->gpr[rs2].tag && (addr & 0xfff0000000000000) != 0xff20000000000000) {
    // if (cap_mem_map_query(&cm_map, addr, &cap)) {
        // overwriting a capability
        // CPUState *cs = env_cpu(env);
        // MemTxResult res;
        // uintptr_t cap_idx = address_space_ldq(cs->as, addr, MEMTXATTRS_UNSPECIFIED, &res);
        // fprintf(stderr, "Bl %u\n", res);
        // assert(res == MEMTX_OK);
        // if (res == MEMTX_OK) {
            // fprintf(stderr, "Cap idx = %lx %lu\n", addr, cap_idx);
            // cap_map_free((int)cap_idx);
        // } else {
        //     fprintf(stderr, "Bad cap %lx\n", addr);
        // }
    // }
    if (env->gpr[rs2].tag && memop_size((MemOp)memop) == 8) {
        // contains a capability
        // int cap_idx = cap_map_alloc();
        // *cap_map_get(cap_idx) = env->gpr[rs2].val.cap;
        uint64_t paddr = (uint64_t)capstone_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
        pthread_mutex_lock(&cr_tree_lock);
        cap_mem_map_add(&cm_map, paddr, &env->gpr[rs2].val.cap);
        pthread_mutex_unlock(&cr_tree_lock);
        // CPUState *cs = env_cpu(env);
        // MemTxResult res;
        // uint64_t r =  address_space_ldq(cs->as, paddr, MEMTXATTRS_UNSPECIFIED, &res);
        // assert(res == MEMTX_OK);
        // assert(r == env->gpr[rs2].val.cap.cursor);
        env->data_to_store_with_cap = env->gpr[rs2].val.scalar;
        // fprintf(stderr, "Encap idx = %lx %d\n\n", addr, cap_idx);
    } else {
        env->data_to_store_with_cap = env->gpr[rs2].val.scalar;
        uint64_t paddr = (uint64_t)capstone_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
        pthread_mutex_lock(&cr_tree_lock);
        cap_mem_map_remove(&cm_map, paddr);
        pthread_mutex_unlock(&cr_tree_lock);
    }
    if (use_cap) {
        _helper_access_with_cap(env, addr, rs1, rs2, memop, true);
    }
}

// check if the location has a capability, if it does, retrieve it from the cap map
void helper_check_cap_load(CPURISCVState *env, uint64_t addr, uint32_t rd, uint32_t memop) {
    reg_overwrite(&cr_tree, &env->gpr[rd]);
    if (memop_size((MemOp)memop) != 8) {
        env->gpr[rd].tag = false;
        return;
    }
    capfat_t cap;
    uint64_t paddr = (uint64_t)capstone_get_haddr(env, (vaddr)addr, MMU_DATA_LOAD);
    pthread_mutex_lock(&cr_tree_lock);
    if (cap_mem_map_query(&cm_map, paddr, &cap)) {
        if (cap.cursor != env->gpr[rd].val.scalar) {
            // FIXME: a hack; is this device address?
            cap_mem_map_remove(&cm_map, paddr);
            // fprintf(stderr, "Bad load %lx != %lx @ %lx (%lx)\n", cap.cursor, env->gpr[rd].val.scalar, addr, paddr);
            // assert(false);
        } else {
            env->gpr[rd].tag = true;
            env->gpr[rd].val.cap = cap;
            // cap_rev_tree_update_refcount(&cr_tree, cap.bounds[0].rev_node, 1);
        }
    } else {
        env->gpr[rd].tag = false;
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

// void helper_reg_set_cap_compressed(CPURISCVState *env, uint32_t rd, uint64_t i64_lo, uint64_t i64_hi) {
//     // CAPSTONE_DEBUG_PRINT("uncompressing capability to reg %u\n", rd);
//     capregval_t *rd_v = &env->gpr[rd];
//     cap_uncompress(i64_lo, i64_hi, &rd_v->val.cap);
//     rd_v->tag = env->load_is_cap;
//     if(rd_v->tag) {
//         memcpy(&rd_v->val.cap.bounds, &env->load_cap_bounds, sizeof(capboundsfat_t));
//     }
// }

// uint64_t helper_compress_cap(CPURISCVState *env, uint32_t reg) {
//     // CAPSTONE_DEBUG_PRINT("compressing capability in reg %u\n", reg);
//     capregval_t *reg_v = &env->gpr[reg];

//     if(!reg_v->tag) {
//         // CAPSTONE_DEBUG_PRINT("attempting to compress non-capability %lx\n", reg_v->val.scalar);
//         // riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
//         env->cap_compress_result_lo = reg_v->val.scalar;
//         env->cap_compress_result_hi = 0;
//         return 0;
//     }

//     cap_compress(&reg_v->val.cap, &env->cap_compress_result_lo, &env->cap_compress_result_hi);
//     return 1;
// }

/* set tag bit for address */
void helper_set_cap_mem_map(CPURISCVState *env, uint32_t reg, uint64_t addr, uint64_t to_set) {
    capregval_t *reg_v = &env->gpr[reg];
    uint64_t paddr = (uint64_t)capstone_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
    pthread_mutex_lock(&cr_tree_lock);
    if (to_set) {
        cap_mem_map_add(&cm_map, paddr, &reg_v->val.cap);
    } else {
        cap_mem_map_remove(&cm_map, paddr);
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_remove_cap_mem_map(CPURISCVState *env, uint64_t addr, uint32_t memop) {
    uint64_t paddr = (uint64_t)capstone_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
    pthread_mutex_lock(&cr_tree_lock);
    cap_mem_map_remove_range(&cm_map, paddr, memop_size((MemOp)memop));
    pthread_mutex_unlock(&cr_tree_lock);
}

/* helpers for Capstone control transfer instructions */

/* Write the content of the specified register into PC reg */
/* This does not touch PC itself */
void helper_set_pc_cap(CPURISCVState *env, uint32_t reg) {
    capregval_t *v = &env->gpr[reg];

    if(!v->tag) {
        CAPSTONE_DEBUG_PRINT("PC cap must be a capability\n");
        riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
    }

    env->pc_cap = v->val.cap;
}

/* helpers for Capstone debug instructions */

void helper_csdebuggencap(CPURISCVState *env, uint32_t rd, uint64_t rs1_v, uint64_t rs2_v) {
    // CAPSTONE_DEBUG_PRINT("Generating cap with (0x%lx, 0x%lx)\n", rs1_v, rs2_v);
    // fprintf(stderr, "G %lx %lx\n", rs1_v, rs2_v);
    assert(rs1_v <= rs2_v);
    capregval_t *rd_v = &env->gpr[rd];
    reg_overwrite(&cr_tree, rd_v);
    capfat_t *cap = &rd_v->val.cap;
    cap_bounds_clear(cap);
    cap->bounds[0].base = rs1_v;
    cap->bounds[0].end = rs2_v;
    cap->cursor = rs1_v;
    cap->async = 0;
    cap->perms = CAP_PERMS_RWX;
    cap->type = CAP_TYPE_LIN;
    pthread_mutex_lock(&cr_tree_lock);
    cap->bounds[0].rev_node = cap_rev_tree_create_lone_node(&cr_tree, true);
    cap->bounds[0].rev_node->range.base = rs1_v;
    cap->bounds[0].rev_node->range.end = rs2_v;
    cap->bounds[0].rev_node->ty = CAP_REV_NODE_TYPE_REF;
    // cap_rev_tree_mark_unsafecell(&cr_tree, cap->bounds[0].rev_node, CAP_REV_NODE_TYPE_UNSAFECELL);
    pthread_mutex_unlock(&cr_tree_lock);
    rd_v->tag = true;
}

void helper_csdebugoncapmem(CPURISCVState *env, uint64_t rs1_v) {
    env->cap_mem = rs1_v != 0;
}

void helper_csdebugclearcmmap(CPURISCVState *env) {
    pthread_mutex_lock(&cr_tree_lock);
    cap_mem_map_clear(&cm_map);
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_csdebugprint(CPURISCVState *env, uint32_t rs1) {
    capregval_t *rs1_v = &env->gpr[rs1];
    pthread_mutex_lock(&cr_tree_lock);
    if(rs1_v->tag) {
        // only printing the bounds for now
        assert(rs1_v->val.cap.bounds[0].rev_node != NULL);
        CAPSTONE_DEBUG_PRINT("Print %u = Cap(valid = %d, mutable = %d, %d, 0x%x, 0x%lx, 0x%lx, 0x%lx, %p)\n",
                            rs1,
                            cap_rev_tree_check_valid(rs1_v->val.cap.bounds[0].rev_node),
                            cap_rev_tree_check_mutable(rs1_v->val.cap.bounds[0].rev_node),
                            rs1_v->val.cap.type,
                            rs1_v->val.cap.perms,
                            rs1_v->val.cap.cursor,
                            rs1_v->val.cap.bounds[0].base,
                            rs1_v->val.cap.bounds[0].end,
                            rs1_v->val.cap.bounds[0].rev_node);
        // print out all ancestors
        cap_rev_node_t *node;
        for(node = rs1_v->val.cap.bounds[0].rev_node; node != NULL; node = node->parent) {
            fprintf(stderr, "> %p: %d %d %lx %lx\n", node, node->valid, node->ty,
                node->range.base, node->range.end);
        }
        for(int i = 1; i < CAP_MAX_PROVENANCE_N; i ++) {
            fprintf(stderr, "* %p\n", rs1_v->val.cap.bounds[i].rev_node);
        }
    } else {
        CAPSTONE_DEBUG_PRINT("Print %u = Scalar(0x%lx)\n", rs1, rs1_v->val.scalar);
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_capstone_debugger(CPURISCVState *env, uint64_t v) {
    if ((v & 0xffffffff) == 0x4ee0c) {
        fprintf(stderr, "Bad\n");
    }
}

void helper_csdebugcount(CPURISCVState *env, uint64_t rs1_v, uint64_t rs2_v) {
    assert(rs1_v < 32);
    env->capstone_debug_counters[rs1_v] += rs2_v;
}

void helper_csdebugcountprint(CPURISCVState *env) {
    CAPSTONE_DEBUG_PRINT("CAPSTONE DEBUG COUNTERS\n");
    int i;
    for(i = 0; i < 32; i ++) {
        CAPSTONE_DEBUG_PRINT("counter[%d] = %lu\n", i, env->capstone_debug_counters[i]);
    }
}

inline static void insert_bounds(capboundsfat_t *dst, capboundsfat_t *src, int *cnt, capaddr_t addr) {
    for(int j = 0; j < CAP_MAX_PROVENANCE_N && src[j].rev_node != NULL;
            j ++) {
        // bool inserted = false;
        int k;
        for(k = 0; k < *cnt && src[j].rev_node != dst[k].rev_node; k ++);
        if(*cnt < CAP_MAX_PROVENANCE_N && k == *cnt) {
            // inserted = true;
            dst[*cnt] = src[j];
            *cnt = *cnt + 1;
        } else if(k == *cnt && !cap_is_far_oob(&src[j], addr)) {
            int h;
            for(h = 0; h < CAP_MAX_PROVENANCE_N && !cap_is_far_oob(&dst[h], addr) &&
                !(dst[h].rev_node->range.base == src[j].rev_node->range.base &&
                  dst[h].rev_node->range.end == src[j].rev_node->range.end &&
                  (src[j].rev_node->alloc_id > dst[h].rev_node->alloc_id ||
                    (src[j].rev_node->alloc_id == dst[h].rev_node->alloc_id && (dst[h].rev_node->depth < src[j].rev_node->depth
                    || (dst[h].rev_node->depth == src[j].rev_node->depth && !dst[h].rev_node->valid))))); h ++);
            // full but we want to force this one in
            if(h < CAP_MAX_PROVENANCE_N) {
                dst[h] = src[j];
                // inserted = true;
            }
        }
        // if(inserted) {
        //     fprintf(stderr, "Inserted %p\n", src[j].rev_node);
        // }
    }
}

void helper_move_cap(CPURISCVState *env, uint64_t v, uint32_t rd_v, uint32_t rs1_v, uint32_t rs2_v) {
    // CAPSTONE_DEBUG_INFO("Cap moved from %u to %u\n", rs1_v, rd_v);
    /* check which is likely to be a valid capability */
    capboundsfat_t t_bounds[CAP_MAX_PROVENANCE_N];
    for(int i = 0; i < CAP_MAX_PROVENANCE_N; i ++)
        t_bounds[i].rev_node = NULL;
    int cnt = 0;
    if (rs1_v != 0 && env->gpr[rs1_v].tag) {
        capfat_t *cap1 = &env->gpr[rs1_v].val.cap;
        insert_bounds(t_bounds, cap1->bounds, &cnt, v);
    }
    if (rs2_v != 0 && env->gpr[rs2_v].tag) {
        capfat_t *cap2 = &env->gpr[rs2_v].val.cap;
        insert_bounds(t_bounds, cap2->bounds, &cnt, v);
    }
    env->gpr[rd_v].val.cap.perms = CAP_PERMS_RWX;
    memcpy(env->gpr[rd_v].val.cap.bounds, t_bounds, sizeof(t_bounds));
    env->gpr[rd_v].val.cap.cursor = v;
    env->gpr[rd_v].tag = true;
}

void helper_reg_overwrite(CPURISCVState *env, uint32_t reg_num) {
    // fprintf(stderr, "O [%u]\n", reg_num);
    reg_overwrite(&cr_tree, &env->gpr[reg_num]);
}
