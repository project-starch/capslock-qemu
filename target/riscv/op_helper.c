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
#include "cap_compress.h"
#include "capstone_helper.h"
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
        env->ctvec.val.cap.bounds.cursor = ctvec_addr;
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

    if (env->cap_mem) {
        pc_redirect_to_capregval(env, &env->cepc);
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

//     rd_v->val.cap.bounds.cursor += offset;
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

//     rd_v->val.cap.bounds.cursor += offset;
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

    rd_v->val.cap.bounds.cursor = cursor;
}

void helper_cslcc(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t imm) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    bool check_passed = true;
    if (imm != 8) {
        check_passed = check_passed && rs1_v->tag;
        check_passed = check_passed && (imm != 2 || rs1_v->val.cap.type != CAP_TYPE_SEALED);
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
            capregval_set_scalar(rd_v, cap_rev_tree_check_valid(&env->cr_tree, rs1_v->val.cap.rev_node_id) ? 1 : 0); // TODO: let's say it's always valid for now
            break;
        case 1:
            capregval_set_scalar(rd_v, (capaddr_t)rs1_v->val.cap.type);
            break;
        case 2:
            capregval_set_scalar(rd_v, rs1_v->val.cap.bounds.cursor);
            break;
        case 3:
            capregval_set_scalar(rd_v, rs1_v->val.cap.bounds.base);
            break;
        case 4:
            capregval_set_scalar(rd_v, rs1_v->val.cap.bounds.end);
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

void helper_csrevoke(CPURISCVState *env, uint32_t rs1) {
    capregval_t *rs1_v = &env->gpr[rs1];

    assert(rs1_v->tag);

    bool is_linear = cap_rev_tree_revoke(&env->cr_tree, rs1_v->val.cap.rev_node_id, true);
    rs1_v->val.cap.type = is_linear ? CAP_TYPE_LIN : CAP_TYPE_UNINIT;
    rs1_v->val.cap.bounds.cursor = rs1_v->val.cap.bounds.base;
}

void helper_csborrow(CPURISCVState *env, uint32_t rd, uint32_t rs1) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    CAPSTONE_DEBUG_INFO("Borrow %u <- %u\n", rd, rs1);

    assert(rs1_v->tag);
    // assert(rs1_v->val.cap.type == CAP_TYPE_LIN);
    cap_rev_tree_revoke(&env->cr_tree, rs1_v->val.cap.rev_node_id, false);

    if(rs1 != rd) {
        *rd_v = *rs1_v;
    }

    rd_v->val.cap.rev_node_id = cap_rev_tree_borrow(&env->cr_tree, rs1_v->val.cap.rev_node_id, false);
}


void helper_csborrowmut(CPURISCVState *env, uint32_t rd, uint32_t rs1) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    CAPSTONE_DEBUG_INFO("Borrowmut %u <- %u\n", rd, rs1);

    assert(rs1_v->tag);
    // assert(rs1_v->val.cap.type == CAP_TYPE_LIN);
    cap_rev_tree_revoke(&env->cr_tree, rs1_v->val.cap.rev_node_id, true);

    if(rs1 != rd) {
        *rd_v = *rs1_v;
    }

    rd_v->val.cap.rev_node_id = cap_rev_tree_borrow(&env->cr_tree, rs1_v->val.cap.rev_node_id, true);
}


void helper_csshrink(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *rs2_v = &env->gpr[rs2];

    assert(rd_v->tag && !rs1_v->tag && !rs2_v->tag);
    assert(rd_v->val.cap.type == CAP_TYPE_LIN || rd_v->val.cap.type == CAP_TYPE_NONLIN ||
           rd_v->val.cap.type == CAP_TYPE_UNINIT);

    capaddr_t base = rs1_v->val.scalar;
    capaddr_t end = rs2_v->val.scalar;

    assert(base < end);
    assert(base >= rd_v->val.cap.bounds.base && end <= rd_v->val.cap.bounds.end);

    rd_v->val.cap.bounds.base = base;
    rd_v->val.cap.bounds.end = end;

    if(rd_v->val.cap.bounds.cursor < base) {
        rd_v->val.cap.bounds.cursor = base;
    } else if(rd_v->val.cap.bounds.cursor > end) {
        rd_v->val.cap.bounds.cursor = end;
    }
}

void helper_csshrinkto(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint64_t size) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    assert(rs1_v->tag);
    assert(rs1_v->val.cap.type == CAP_TYPE_LIN || rs1_v->val.cap.type == CAP_TYPE_NONLIN ||
           rs1_v->val.cap.type == CAP_TYPE_UNINIT);
    assert(rs1_v->val.cap.bounds.cursor >= rs1_v->val.cap.bounds.base &&
            rs1_v->val.cap.bounds.cursor + size <= rs1_v->val.cap.bounds.end);

    *rd_v = *rs1_v;
    rd_v->val.cap.bounds.base = rd_v->val.cap.bounds.cursor;
    rd_v->val.cap.bounds.end = rd_v->val.cap.bounds.cursor + size;
}

void helper_cssplit(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *rs2_v = &env->gpr[rs2];

    assert(rs1_v->tag && !rs2_v->tag);
    assert(rs1_v->val.cap.type == CAP_TYPE_LIN || rs1_v->val.cap.type == CAP_TYPE_NONLIN);

    capaddr_t mid = rs2_v->val.scalar;

    assert(mid > rs1_v->val.cap.bounds.base && mid < rs1_v->val.cap.bounds.end);

    bool mutable = cap_rev_tree_check_mutable(&env->cr_tree, rs1_v->val.cap.rev_node_id);
    cap_rev_tree_revoke(&env->cr_tree, rs1_v->val.cap.rev_node_id, mutable);

    if(rs1 != rd) {
        *rd_v = *rs1_v;

        rs1_v->val.cap.bounds.end = mid;
        rs1_v->val.cap.bounds.cursor = rs1_v->val.cap.bounds.base;

        rd_v->val.cap.bounds.base = mid;
        rd_v->val.cap.bounds.cursor = mid;
        rd_v->val.cap.rev_node_id = cap_rev_tree_split(&env->cr_tree, &rs1_v->val.cap.rev_node_id);
    }
}

void helper_cstighten(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t perms) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    assert(rs1_v->tag);
    assert(rs1_v->val.cap.type == CAP_TYPE_LIN || rs1_v->val.cap.type == CAP_TYPE_NONLIN ||
           rs1_v->val.cap.type == CAP_TYPE_UNINIT);

    capperms_t perms_p = perms > 7 ? CAP_PERMS_NA : (capperms_t)perms;

    assert(cap_perms_allow(rs1_v->val.cap.perms, perms_p));

    if(rs1 != rd) {
        *rd_v = *rs1_v;
        if(!captype_is_copyable(rs1_v->val.cap.type)) {
            *rs1_v = CAPREGVAL_NULL;
        }
    }

    rd_v->val.cap.perms = perms_p;

    if(rd_v->val.cap.type == CAP_TYPE_LIN && !cap_perms_allow(rd_v->val.cap.perms, CAP_PERMS_WO)) {
        // immutable linear capability can be safely invalidated without
        // scrubbing the data
        cap_rev_tree_delin(&env->cr_tree, rd_v->val.cap.rev_node_id);
    }
}

void helper_csdrop(CPURISCVState *env, uint32_t rs1) {
    capregval_t *rs1_v = &env->gpr[rs1];

    if (rs1_v->tag) {
        cap_rev_tree_revoke(&env->cr_tree, rs1_v->val.cap.rev_node_id, true);
        cap_rev_tree_invalidate(&env->cr_tree, rs1_v->val.cap.rev_node_id);
    }
}

void helper_csinit(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *rs2_v = &env->gpr[rs2];

    assert(rs1_v->tag && !rs2_v->tag);
    assert(rs1_v->val.cap.type == CAP_TYPE_UNINIT);
    assert(rs1_v->val.cap.bounds.cursor == rs1_v->val.cap.bounds.end);

    capaddr_t offset = rs2_v->val.scalar;

    if(rs1 != rd) {
        *rd_v = *rs1_v;
        if(!captype_is_copyable(rs1_v->val.cap.type)) {
            *rs1_v = CAPREGVAL_NULL;
        }
    }

    rd_v->val.cap.type = CAP_TYPE_LIN;
    rd_v->val.cap.bounds.cursor = rd_v->val.cap.bounds.base + offset;
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

    if(cap_size(&rs1_v->val.cap.bounds) < CAP_SEALED_SIZE_MIN ||
       !cap_aligned(&rs1_v->val.cap.bounds, 4)) {
        CAPSTONE_DEBUG_PRINT("Sealing requires an aligned region of sufficient size\n");
    }

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
    *rd_v = tmp;

    if(needs_tlb_flush) {
        tlb_flush(cpu);
    }
}

/* Capability-based memory access */

#define CAPSTONE_IMM12_SEXT(x) ((x) | (((-((x) >> 11)) << 12)))

// #define CAPSTONE_EXCP_IS_BREAKPOINT

inline static void riscv_raise_exception_bp(CPURISCVState *env, RISCVException excp, uintptr_t pc) {
    #ifdef CAPSTONE_EXCP_IS_BREAKPOINT
        riscv_raise_exception(env, RISCV_EXCP_BREAKPOINT, pc);
    #else
        riscv_raise_exception(env, excp, pc);
    #endif
}

static void _helper_access_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t rs2, uint32_t memop, bool is_store) {
    // CAPSTONE_DEBUG_PRINT("Cap mem access %u %lx\n", rs1, imm);

    capregval_t *rs1_v = &env->gpr[rs1];

    unsigned size = memop_size((MemOp)memop);

    if(rs1_v->tag) {
        capfat_t *cap = &rs1_v->val.cap;

        CAPSTONE_DEBUG_INFO("Memacc (%s) with cap at %lx %lu\n", is_store ? "store" : "load", addr, (capaddr_t)size);
        // CAPSTONE_DEBUG_PRINT("Cap mem access addr = %lx, size = %lu\n", addr, (capaddr_t)size);
        // TODO: bounds check only for now
        if(!cap_in_bounds(&cap->bounds, addr, (capaddr_t)size)) {
            CAPSTONE_DEBUG_PRINT("Cap mem access OOB: addr = %lx, size = %lu, bounds = (%lx, %lx) @ pc = %lx\n", addr, (capaddr_t)size,
                cap->bounds.base, cap->bounds.end, env->pc);
            RISCVException excp = is_store ? RISCV_EXCP_STORE_AMO_ACCESS_FAULT : RISCV_EXCP_LOAD_ACCESS_FAULT;
            riscv_raise_exception_bp(env, excp, GETPC());
        }

        if (is_store && !cap_rev_tree_check_mutable(&env->cr_tree, cap->rev_node_id)) {
            CAPSTONE_DEBUG_PRINT("Attempting to use immutable or invalid capability for store!\n");
            riscv_raise_exception_bp(env, RISCV_EXCP_STORE_AMO_ACCESS_FAULT, GETPC());
        }

        if (!is_store && !cap_rev_tree_check_valid(&env->cr_tree, cap->rev_node_id)) {
            CAPSTONE_DEBUG_PRINT("Attempting to use an invalid capability for load!\n");
            riscv_raise_exception_bp(env, RISCV_EXCP_LOAD_ACCESS_FAULT, GETPC());
        }

        cap_rev_tree_revoke(&env->cr_tree, rs1_v->val.cap.rev_node_id, is_store);
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
            env->load_is_cap = cap_mem_map_query(&env->cm_map, addr, &env->load_cap_bounds);
            if(env->load_is_cap) {
                CAPSTONE_DEBUG_INFO("Cap loaded from %lx\n", addr);
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


void helper_store_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t rs2,
                        uint32_t memop, uint32_t use_cap) {
    // if (rs2 == 10 && lcced) {
    //     CAPSTONE_DEBUG_PRINT("x10 stored to 0x%lx\n", addr);
    // }
    // if (env->gpr[rs2].tag && (addr & 0xfff0000000000000) != 0xff20000000000000) {
    if (env->gpr[rs2].tag) {
        // contains a capability
        int cap_idx = cap_map_alloc();
        *cap_map_get(cap_idx) = env->gpr[rs2].val.cap;
        cap_mem_map_add(&env->cm_map, addr, &env->gpr[rs2].val.cap.bounds);
        env->data_to_store_with_cap = cap_idx;
    } else {
        env->data_to_store_with_cap = env->gpr[rs2].val.scalar;
        cap_mem_map_remove(&env->cm_map, addr);
    }
    if (use_cap) {
        _helper_access_with_cap(env, addr, rs1, rs2, memop, true);
    }
}

// check if the location has a capability, if it does, retrieve it from the cap map
void helper_check_cap_load(CPURISCVState *env, uint64_t addr, uint32_t rd) {
    if (cap_mem_map_query(&env->cm_map, addr, NULL)) {
        env->gpr[rd].tag = true;
        env->gpr[rd].val.cap = *cap_map_get((int)env->gpr[rd].val.scalar);
    } else {
        env->gpr[rd].tag = false;
    }
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
    if (to_set) {
        cap_mem_map_add(&env->cm_map, addr, &reg_v->val.cap.bounds);
    } else {
        cap_mem_map_remove(&env->cm_map, addr);
    }
}

void helper_remove_cap_mem_map(CPURISCVState *env, uint64_t addr, uint32_t memop) {
    cap_mem_map_remove_range(&env->cm_map, addr, memop_size((MemOp)memop));
}

/* helpers for Capstone control transfer instructions */

void helper_cjalr_switch_caps(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint64_t succ_pc) {
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];

    // rd <- pc <- rs1
    capfat_t pc_cap_v = env->pc_cap;
    if(!rs1_v->tag) {
        CAPSTONE_DEBUG_PRINT("cs.cjalr requires capability in rs1\n");
        riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
    }

    env->pc_cap = rs1_v->val.cap;

    pc_cap_v.bounds.cursor = succ_pc;
    rd_v->val.cap = pc_cap_v;
    rd_v->tag = true;
}

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


void helper_cscall(CPURISCVState *env, uint32_t rd, uint32_t rs1) {
    assert(rd == rs1);

    CPUState *cs = env_cpu(env);
    capregval_t *rs1_v;
    if(rs1 == 0) {
        rs1_v = &env->cih;
    } else {
        rs1_v = &env->gpr[rs1];
    }

    if(!rs1_v->tag) {
        CAPSTONE_DEBUG_PRINT("Call requires a capability\n");
        riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
    }

    if(rs1_v->val.cap.type != CAP_TYPE_SEALED ||
       rs1_v->val.cap.async != CAP_ASYNC_SYNC) {
        CAPSTONE_DEBUG_PRINT("Call requires a sealel sync capability\n");
        riscv_raise_exception(env, RISCV_EXCP_UNEXP_CAP_TYPE, GETPC());
    }

    capfat_t rs1_val = rs1_v->val.cap;
    rs1_v->tag = false; /* always linear */

    trace_capstone_dom_switch_sync();
    swap_c_effective_regs(cs->as, env, rs1_val.bounds.base, env->pc);

    // set cra
    rs1_val.type = CAP_TYPE_SEALEDRET;
    rs1_val.bounds.cursor = rs1_val.bounds.base;
    rs1_val.async = CAP_ASYNC_SYNC;
    rs1_val.reg = rd;
    capregval_set_cap(&env->gpr[1], &rs1_val);
}

void helper_csreturn(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    CPUState *cs = env_cpu(env);
    capregval_t *rd_v = &env->gpr[rd];
    capregval_t *rs1_v = &env->gpr[rs1];
    capregval_t *rs2_v = &env->gpr[rs2];

    if(rd == 0) {
        if(rs1_v->tag) {
            CAPSTONE_DEBUG_PRINT("Return requires an integer as rs1\n");
            riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
        }

        env->pc_cap.bounds.cursor = rs1_v->val.scalar;
        capregval_set_cap(&env->ctvec, &env->pc_cap);
        cap_set_capregval(&env->pc_cap, &env->cepc);
        env->pc = env->pc_cap.bounds.cursor;
        if(env->pc_cap.type != CAP_TYPE_NONLIN) {
            env->cepc = CAPREGVAL_NULL;
        }
    } else {
        if(!rd_v->tag || rs1_v->tag) {
            CAPSTONE_DEBUG_PRINT("Return requires a capability and an integer\n");
            riscv_raise_exception(env, RISCV_EXCP_UNEXP_OP_TYPE, GETPC());
        }

        if(rd_v->val.cap.type != CAP_TYPE_SEALEDRET && rd_v->val.cap.type != CAP_TYPE_SEALED) {
            CAPSTONE_DEBUG_PRINT("Return requires a sealed-return capability\n");
            riscv_raise_exception(env, RISCV_EXCP_UNEXP_CAP_TYPE, GETPC());
        }

        capfat_t rd_cap = rd_v->val.cap;
        if(rd_cap.type == CAP_TYPE_SEALED) {
            rd_cap.reg = 0;
        }
        capaddr_t base_addr = rd_cap.bounds.base;
        uint64_t rs2_val = rs2_v->val.scalar;

        switch(rd_cap.async) {
            case CAP_ASYNC_SYNC:
                if(rd_cap.reg == 0 && env->cih.tag) {
                    // cih already contains a capability
                    // invalid operation
                    CAPSTONE_DEBUG_PRINT("Return to synchronous sealed-return cap with reg = 0 is only allowed when cih = cnull\n");
                    riscv_raise_exception(env, RISCV_EXCP_UNEXP_CAP_TYPE, GETPC());
                }

                *rd_v = CAPREGVAL_NULL;

                trace_capstone_dom_switch_sync();
                swap_c_effective_regs(cs->as, env, base_addr, rs1_v->val.scalar);

                // write return reg
                if(rd_cap.reg == 0) {
                    assert(!env->cih.tag);
                    capregval_set_cap(&env->cih, &rd_cap);
                    env->cih.val.cap.type = CAP_TYPE_SEALED;
                    // also deliver the V-interrupts

                    QEMU_IOTHREAD_LOCK_GUARD();
                    env->mip |= rs2_val;
                    riscv_cpu_check_interrupts(env);
                } else {
                    capregval_set_cap(&env->gpr[rd_cap.reg], &rd_cap);
                    env->gpr[rd_cap.reg].val.cap.type = CAP_TYPE_SEALED;
                }

                break;
            case CAP_ASYNC_ASYNC:
                rd_cap.type = CAP_TYPE_SEALED;
                rd_cap.async = CAP_ASYNC_SYNC;
                capregval_set_cap(&env->cih, &rd_cap);
                *rd_v = CAPREGVAL_NULL;

                trace_capstone_dom_switch_async(0);
                swap_domain_scoped_regs(cs->as, env, base_addr, rs1_v->val.scalar, DOM_SCOPED_SWAP_IN);

                // post the interrupts
                QEMU_IOTHREAD_LOCK_GUARD();
                env->mip |= rs2_val;
                riscv_cpu_check_interrupts(env);

                break;
            default:
                assert(false);
        }
    }
}

void helper_cscapenter(CPURISCVState *env, uint32_t rs1, uint32_t rs2) {
    // enters the capability mode
    env->cap_mem = true;

    // generates the genesis capabilities
    assert(rs1 && rs2); // we do not allow the platform-dependent case for now
    uint64_t pc_lo_addr = env->gpr[rs1].val.scalar;
    uint64_t pc_hi_addr = env->gpr[rs2].val.scalar;
    assert(pc_lo_addr < pc_hi_addr);

    env->pc_cap.bounds.base = pc_lo_addr;
    env->pc_cap.bounds.end = pc_hi_addr;
    env->pc_cap.type = CAP_TYPE_LIN;
    env->pc_cap.perms = CAP_PERMS_RWX;

    env->gpr[10].tag = 1;
    env->gpr[10].val.cap.bounds.base = 0;
    env->gpr[10].val.cap.bounds.end = pc_lo_addr;
    env->gpr[10].val.cap.type = CAP_TYPE_LIN;
    env->gpr[10].val.cap.perms = CAP_PERMS_RWX;

    env->gpr[11].tag = 1;
    env->gpr[11].val.cap.bounds.base = pc_hi_addr;
    env->gpr[11].val.cap.bounds.end = (uint64_t)1 << 63; // TODO: should be 2**64
    env->gpr[11].val.cap.type = CAP_TYPE_LIN;
    env->gpr[11].val.cap.perms = CAP_PERMS_RWX;

    cap_rev_tree_init(&env->cr_tree, &env->pc_cap.rev_node_id,
        &env->gpr[10].val.cap.rev_node_id, &env->gpr[11].val.cap.rev_node_id);
}


/* helpers for Capstone debug instructions */

void helper_csdebuggencap(CPURISCVState *env, uint32_t rd, uint64_t rs1_v, uint64_t rs2_v) {
    // CAPSTONE_DEBUG_PRINT("Generating cap with (0x%lx, 0x%lx)\n", rs1_v, rs2_v);
    capregval_t *rd_v = &env->gpr[rd];
    capfat_t *cap = &rd_v->val.cap;
    cap->bounds.base = rs1_v;
    cap->bounds.end = rs2_v;
    cap->bounds.cursor = rs1_v;
    cap->async = 0;
    cap->perms = CAP_PERMS_RWX;
    cap->type = CAP_TYPE_LIN;
    cap->rev_node_id = cap_rev_tree_create_lone_node(&env->cr_tree, true);
    rd_v->tag = true;
}

void helper_csdebugoncapmem(CPURISCVState *env, uint64_t rs1_v) {
    env->cap_mem = rs1_v != 0;
}

void helper_csdebugclearcmmap(CPURISCVState *env) {
    cap_mem_map_clear(&env->cm_map);
}

void helper_csdebugprint(CPURISCVState *env, uint32_t rs1) {
    capregval_t *rs1_v = &env->gpr[rs1];
    if(rs1_v->tag) {
        // only printing the bounds for now
        CAPSTONE_DEBUG_PRINT("Print %u = Cap(%d, %d, 0x%x, 0x%lx, 0x%lx, 0x%lx)\n",
                            rs1,
                            cap_rev_tree_check_valid(&env->cr_tree, rs1_v->val.cap.rev_node_id),
                            rs1_v->val.cap.type,
                            rs1_v->val.cap.perms,
                            rs1_v->val.cap.bounds.cursor,
                            rs1_v->val.cap.bounds.base,
                            rs1_v->val.cap.bounds.end);
    } else {
        CAPSTONE_DEBUG_PRINT("Print %u = Scalar(0x%lx)\n", rs1, rs1_v->val.scalar);
    }
}

void helper_capstone_debugger(void) {
    CAPSTONE_DEBUG_PRINT("DEBUGGER\n");
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

void helper_move_cap(CPURISCVState *env, uint64_t v, uint32_t rd_v, uint32_t rs1_v) {
    CAPSTONE_DEBUG_INFO("Cap moved from %u to %u\n", rs1_v, rd_v);
    env->gpr[rd_v].val = env->gpr[rs1_v].val;
    env->gpr[rd_v].val.scalar = v;
}


