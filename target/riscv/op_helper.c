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
#include "capslock_defs.h"
#include "cap_mem_map.h"
#include "cap_rev_tree.h"
#include "trace.h"

static void print_stack_trace(CPURISCVState *env);

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

inline static void riscv_raise_exception_bp(CPURISCVState *env, RISCVException excp, uintptr_t pc) {
    #ifdef CAPSLOCK_EXCP_IS_BREAKPOINT
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

    target_ulong retpc = env->mepc;
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

/* CapsLock helpers */

static void cap_generate(capregval_t *v, uint64_t base, uint64_t end) {
    capfat_t *cap = &v->val.cap;
    cap_bounds_clear(cap);
    cap->bounds[0].base = base;
    cap->bounds[0].end = end;
    cap->cursor = base;
    cap->async = 0;
    cap->perms = CAP_PERMS_RWX;
    cap->type = CAP_TYPE_LIN;
    pthread_mutex_lock(&cr_tree_lock);
    cap->bounds[0].rev_node = cap_rev_tree_create_lone_node(&cr_tree, true);
    cap->bounds[0].rev_node->range.base = base;
    cap->bounds[0].rev_node->range.end = end;
    cap->bounds[0].rev_node->ty = CAP_REV_NODE_TYPE_REF;
    // cap_rev_tree_mark_unsafecell(&cr_tree, cap->bounds[0].rev_node, CAP_REV_NODE_TYPE_UNSAFECELL);
    pthread_mutex_unlock(&cr_tree_lock);
    v->tag = true;
}

static capregval_t *cap_stack_lookup(CPURISCVState *env, uint64_t addr, capregval_t *df) {
    int idx;
    for(idx = env->sp_stack_n - 1; idx >= 0 && env->sp_stack[idx].val.scalar <= addr; -- idx);
    if (idx + 1 < env->sp_stack_n && env->sp_stack[idx + 1].val.cap.bounds[0].base <= addr &&
        env->sp_stack[idx + 1].val.cap.bounds[0].end > addr)
    {
        return &env->sp_stack[idx + 1];
    } else {
        return df;
    }
}

static void drop_impl(CPURISCVState *env, capregval_t *rv, bool is_stack) {
    if (rv->tag) {
        pthread_mutex_lock(&cr_tree_lock);
        bool is_far_oob;
        bool found = cap_bounds_collapse(&cr_tree, rv->val.cap.bounds, rv->val.scalar, 1, &is_far_oob);
        if (found && cap_rev_tree_check_valid(rv->val.cap.bounds[0].rev_node)) {
            // find the root of the tree which is the owner of the allocation
            cap_rev_node_t *root;
            for(root = rv->val.cap.bounds[0].rev_node; root->parent != NULL; root = root->parent);
            cap_rev_tree_revoke(&cr_tree, root, env->gpr[xRA].val.scalar);
        } else if (!is_far_oob) {
            CAPSLOCK_DEBUG_PRINT("Attempting to drop an invalid capability! %lx %p in %d @ %lx, previously invalidated at %lx\n", rv->val.scalar,
                rv->val.cap.bounds[0].rev_node, getpid(), env->pc, rv->val.cap.bounds[0].rev_node->pc_invalidate);
            print_stack_trace(env);
            riscv_raise_exception(env, RISCV_EXCP_INVALID_CAP, GETPC());
        } else
            rv->tag = false;
        pthread_mutex_unlock(&cr_tree_lock);
    }
}

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
        check_passed = check_passed && (imm != 4 || (rs1_v->val.cap.type != CAP_TYPE_SEALED && rs1_v->val.cap.type != CAP_TYPE_SEALEDRET));
        check_passed = check_passed && (imm != 5 || (rs1_v->val.cap.type != CAP_TYPE_SEALED && rs1_v->val.cap.type != CAP_TYPE_SEALEDRET));
        check_passed = check_passed && (imm != 6 || rs1_v->val.cap.type == CAP_TYPE_SEALED || rs1_v->val.cap.type == CAP_TYPE_SEALEDRET);
        check_passed = check_passed && (imm != 7 || rs1_v->val.cap.type == CAP_TYPE_SEALEDRET);
    }
    if (!check_passed) {
        CAPSLOCK_DEBUG_PRINT("Invalid operands to lcc!\n");
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

void helper_csrevoke(CPURISCVState *env, uint32_t rs1) {
    assert(false && "Not supposed to be used");
    capregval_t *rs1_v = &env->gpr[rs1];

    assert(rs1_v->tag);

    pthread_mutex_lock(&cr_tree_lock);
    bool bounds_found = cap_bounds_collapse(&cr_tree, rs1_v->val.cap.bounds, rs1_v->val.cap.cursor, 1, NULL);

    if(bounds_found) {
        cap_rev_tree_revoke(&cr_tree, rs1_v->val.cap.bounds[0].rev_node, env->gpr[xRA].val.scalar);
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

    if(bounds_found) {
        if(!cap_rev_tree_check_valid(rs1_v->val.cap.bounds[0].rev_node)) {
            CAPSLOCK_DEBUG_PRINT("Attempting to borrow from an invalid capability (node = %p, %ld) addr = %lx, size = %lu @ pc = %lx\n!"
                "Previously invalidated at %lx\n",
                rs1_v->val.cap.bounds[0].rev_node,
                rs1_v->val.cap.bounds[0].rev_node - cr_tree.node_pool,
                rs1_v->val.scalar,
                rs2_v->val.scalar,
                env->gpr[xRA].val.scalar,
                rs1_v->val.cap.bounds[0].rev_node->pc_invalidate);
            print_stack_trace(env);
            for(cap_rev_node_t *node = rs1_v->val.cap.bounds[0].rev_node; node != NULL; node = node->parent) {
                fprintf(stderr, "> %p: %d %d %lx %lx\n", node, node->valid, node->ty,
                    node->range.base, node->range.end);
            }
            pthread_mutex_unlock(&cr_tree_lock);
            riscv_raise_exception_bp(env, RISCV_EXCP_INVALID_CAP, GETPC());
        }

        uintptr_t base = rs1_v->val.scalar;
        uintptr_t end;
        if (rs2_v->val.scalar == 0) {
            // foreign type, we don't know anything about it
            // just inherit
            end = rs1_v->val.cap.bounds[0].end;
        } else {
            end = rs1_v->val.scalar + rs2_v->val.scalar;
        }

        cap_rev_node_t *from_node = rs1_v->val.cap.bounds[0].rev_node;
        if(rs1 != rd) {
            *rd_v = *rs1_v;
        }
        for (int i = 1; i < CAP_MAX_PROVENANCE_N; i ++)
            rd_v->val.cap.bounds[i].rev_node = NULL;
        rd_v->val.cap.bounds[0].rev_node = cap_rev_tree_borrow(&cr_tree, from_node, mutable,
            base, end);
        rd_v->val.cap.bounds[0].base = base;
        rd_v->val.cap.bounds[0].end = end;
    } else {
        rs1_v -> tag = false;
        *rd_v = *rs1_v;
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_csborrow(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    CAPSLOCK_DEBUG_INFO("Borrow %u <- %u\n", rd, rs1);
    borrow_impl(env, rd, rs1, rs2, false);
}


void helper_csborrowmut(CPURISCVState *env, uint32_t rd, uint32_t rs1, uint32_t rs2) {
    CAPSLOCK_DEBUG_INFO("Borrowmut %u <- %u\n", rd, rs1);
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
        assert(base <= end);

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
    CAPSLOCK_DEBUG_INFO("Dropping capability in %u\n", rs1);
    capregval_t *rs1_v = &env->gpr[rs1];

    drop_impl(env, rs1_v, false);
}

void helper_csloadsp(CPURISCVState *env, uint32_t rd, uint32_t rs) {
    uint64_t addr = env->gpr[rs].val.scalar;
    capregval_t *v = cap_stack_lookup(env, addr, &env->gpr[rs]);
    env->gpr[rd] = *v;
    env->gpr[rd].val.scalar = addr;
}

void helper_csgencapstack(CPURISCVState *env, uint32_t rs, uint64_t size) {
    uint64_t base = env->gpr[rs].val.scalar;
    uint64_t end = base + size;

    // pop stuff that's already below the stack pointer
    while (env->sp_stack_n > 0 && env->sp_stack[env->sp_stack_n - 1].val.scalar < end) {
        -- env->sp_stack_n;
        cap_rev_tree_revoke(&cr_tree, env->sp_stack[env->sp_stack_n].val.cap.bounds[0].rev_node, env->gpr[xRA].val.scalar);
        pthread_mutex_lock(&cr_tree_lock);
        cap_rev_tree_update_refcount_cap(&env->sp_stack[env->sp_stack_n].val.cap, -1);
        pthread_mutex_unlock(&cr_tree_lock);
    }
    assert(env->sp_stack_n < SP_STACK_SIZE);

    cap_generate(&env->sp_stack[env->sp_stack_n], base, end);
    assert(env->sp_stack[env->sp_stack_n].tag && cap_rev_tree_check_valid(env->sp_stack[env->sp_stack_n].val.cap.bounds[0].rev_node));
    pthread_mutex_lock(&cr_tree_lock);
    cap_rev_tree_update_refcount_cap(&env->sp_stack[env->sp_stack_n].val.cap, 1);
    pthread_mutex_unlock(&cr_tree_lock);
    ++ env->sp_stack_n;
}

/* Capability-based memory access */

#define CAPSLOCK_IMM12_SEXT(x) ((x) | (((-((x) >> 11)) << 12)))

inline static void print_bounds(capfat_t *cap) {
    for (int i = 0; i < CAP_MAX_PROVENANCE_N; i ++) {
        if (cap->bounds[i].rev_node != NULL) {
            CAPSLOCK_DEBUG_PRINT("Bounds %d: %lx -- %lx (valid = %d, unsafecell = %d) @ %p\n", i, cap->bounds[i].base, cap->bounds[i].end,
                cap_rev_tree_check_valid(cap->bounds[i].rev_node), cap_rev_tree_is_unsafe_cell(cap->bounds[i].rev_node), cap->bounds[i].rev_node);
            CAPSLOCK_DEBUG_PRINT("Parents unsafecell:\n");
            for(cap_rev_node_t *cur = cap->bounds[i].rev_node->parent; cur != NULL; cur = cur->parent) {
                CAPSLOCK_DEBUG_PRINT("Ty = %d, bounds = %lx -- %lx @%p\n", cur->ty,
                    cur->range.base, cur->range.end, cur);
            }
        }
    }
}

static void _helper_access_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t rs2, uint32_t memop, bool is_store) {
    capregval_t *rs1_v;

    if (rs1 == xSP) {
        rs1_v = cap_stack_lookup(env, addr, &env->gpr[rs1]);
    } else {
        rs1_v = &env->gpr[rs1];
    }

    unsigned size = memop_size((MemOp)memop);

    if(rs1_v->tag) {
        capfat_t *cap = &rs1_v->val.cap;
        bool bounds_found, is_far_oob;
        pthread_mutex_lock(&cr_tree_lock);
        bounds_found = cap_bounds_collapse(&cr_tree, cap->bounds, addr, (capaddr_t)size, &is_far_oob);
        if (bounds_found) {
            if (is_store && !cap_rev_tree_check_valid(cap->bounds[0].rev_node)) {
                CAPSLOCK_DEBUG_PRINT("Attempting to use invalid capability for store (address = %lx, size = %x, node = %p) @ pc = %lx!\n"
                    "Previously invalidated at %lx\n",
                    addr, size,
                    cap->bounds[0].rev_node,
                    env->pc,
                    cap->bounds[0].rev_node->pc_invalidate);
                print_stack_trace(env);
                print_bounds(cap);
                pthread_mutex_unlock(&cr_tree_lock);
                riscv_raise_exception_bp(env, RISCV_EXCP_STORE_AMO_ACCESS_FAULT, GETPC());
            }

            if (!is_store && !cap_rev_tree_check_valid(cap->bounds[0].rev_node)) {
                CAPSLOCK_DEBUG_PRINT("Attempting to use an invalid capability for load (address = %lx, size = %x, node = %p) @ pc = %lx!\n"
                    "Previously invalidated at %lx\n",
                    addr, size,
                    cap->bounds[0].rev_node,
                    env->pc,
                    cap->bounds[0].rev_node->pc_invalidate
                );
                print_stack_trace(env);
                print_bounds(cap);
                pthread_mutex_unlock(&cr_tree_lock);
                riscv_raise_exception_bp(env, RISCV_EXCP_LOAD_ACCESS_FAULT, GETPC());
            }

            cap_rev_node_range_t range;
            range.base = addr;
            range.end = addr + size;
            assert(cap_rev_tree_access(&cr_tree, cap->bounds[0].rev_node, &range, is_store, env->pc));
        } else {
            env->gpr[rs1].tag = false;
        }
        pthread_mutex_unlock(&cr_tree_lock);
    }


    if(size == 8) {
        // accessing capabilities in memory, extra checks needed
        // check alignment
        if(is_store) {
            if(env->gpr[rs2].tag) {
                CAPSLOCK_DEBUG_INFO("Cap stored to 0x%lx from %u\n", addr, rs2);
            }
            if (env->gpr[rs2].tag && (addr & 7)) {
                CAPSLOCK_DEBUG_PRINT("Unaligned cap access (addr = 0x%lx)\n", addr);
                riscv_raise_exception(env, RISCV_EXCP_STORE_AMO_ADDR_MIS, GETPC());
            }
        } else {
            uint64_t paddr = (uint64_t)capslock_get_haddr(env, (vaddr)addr, MMU_DATA_LOAD);
            pthread_mutex_lock(&cr_tree_lock);
            env->load_is_cap = cap_mem_map_query(&cm_map, paddr, NULL);
            pthread_mutex_unlock(&cr_tree_lock);
            if(env->load_is_cap) {
                CAPSLOCK_DEBUG_INFO("Cap loaded from %lx (paddr = %lx, pc = %lx)\n", addr, paddr, env->pc);
            }
            if(env->load_is_cap && (addr & 7)) {
                CAPSLOCK_DEBUG_PRINT("Unaligned cap access (addr = 0x%lx)\n", addr);
                riscv_raise_exception(env, RISCV_EXCP_LOAD_ADDR_MIS, GETPC());
            }
        }
    }

}

void helper_load_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t memop) {
    _helper_access_with_cap(env, addr, rs1, 0, memop, false);
}

void helper_cap_scrub(CPURISCVState *env, uint64_t addr) {
    uint64_t paddr = (uint64_t)capslock_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
    pthread_mutex_lock(&cr_tree_lock);
    cap_mem_map_remove(&cm_map, paddr);
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_store_with_cap(CPURISCVState *env, uint64_t addr, uint32_t rs1, uint32_t rs2,
                        uint32_t memop, uint32_t use_cap) {
    if (env->gpr[rs2].tag && memop_size((MemOp)memop) == 8) {
        // contains a capability
        uint64_t paddr = (uint64_t)capslock_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
        pthread_mutex_lock(&cr_tree_lock);
        cap_mem_map_add(&cm_map, paddr, &env->gpr[rs2].val.cap);
        pthread_mutex_unlock(&cr_tree_lock);
        env->data_to_store_with_cap = env->gpr[rs2].val.scalar;
    } else {
        env->data_to_store_with_cap = env->gpr[rs2].val.scalar;
        uint64_t paddr = (uint64_t)capslock_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
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
    if (memop_size((MemOp)memop) != 8) {
        env->gpr[rd].tag = false;
        return;
    }
    capfat_t cap;
    uint64_t paddr = (uint64_t)capslock_get_haddr(env, (vaddr)addr, MMU_DATA_LOAD);
    pthread_mutex_lock(&cr_tree_lock);
    if (cap_mem_map_query(&cm_map, paddr, &cap)) {
        if (cap.cursor != env->gpr[rd].val.scalar) {
            cap_mem_map_remove(&cm_map, paddr);
        } else {
            env->gpr[rd].tag = true;
            env->gpr[rd].val.cap = cap;
        }
    } else {
        env->gpr[rd].tag = false;
    }
    pthread_mutex_unlock(&cr_tree_lock);
}
/* set tag bit for address */
void helper_set_cap_mem_map(CPURISCVState *env, uint32_t reg, uint64_t addr, uint64_t to_set) {
    capregval_t *reg_v = &env->gpr[reg];
    uint64_t paddr = (uint64_t)capslock_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
    pthread_mutex_lock(&cr_tree_lock);
    if (to_set) {
        cap_mem_map_add(&cm_map, paddr, &reg_v->val.cap);
    } else {
        cap_mem_map_remove(&cm_map, paddr);
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_remove_cap_mem_map(CPURISCVState *env, uint64_t addr, uint32_t memop) {
    uint64_t paddr = (uint64_t)capslock_get_haddr(env, (vaddr)addr, MMU_DATA_STORE);
    pthread_mutex_lock(&cr_tree_lock);
    cap_mem_map_remove_range(&cm_map, paddr, memop_size((MemOp)memop));
    pthread_mutex_unlock(&cr_tree_lock);
}

/* helpers for CapsLock control transfer instructions */

/* helpers for CapsLock debug instructions */

void helper_csdebuggencap(CPURISCVState *env, uint32_t rd, uint64_t rs1_v, uint64_t rs2_v) {
    assert(rs1_v <= rs2_v);
    capregval_t *rd_v = &env->gpr[rd];
    // reg_overwrite(&cr_tree, rd_v);
    cap_generate(rd_v, rs1_v, rs2_v);
}

void helper_csdebugprint(CPURISCVState *env, uint32_t rs1) {
    capregval_t *rs1_v = &env->gpr[rs1];
    pthread_mutex_lock(&cr_tree_lock);
    if(rs1_v->tag) {
        assert(rs1_v->val.cap.bounds[0].rev_node != NULL);
        CAPSLOCK_DEBUG_PRINT("Print %u = Cap(valid = %d, mutable = %d, %d, 0x%x, 0x%lx, 0x%lx, 0x%lx, %p)\n",
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
        CAPSLOCK_DEBUG_PRINT("Print %u = Scalar(0x%lx)\n", rs1, rs1_v->val.scalar);
    }
    pthread_mutex_unlock(&cr_tree_lock);
}

void helper_capslock_debugger(CPURISCVState *env, uint64_t v) {
}

void helper_csdebugcount(CPURISCVState *env, uint64_t rs1_v, uint64_t rs2_v) {
    assert(rs1_v < 32);
    env->capslock_debug_counters[rs1_v] += rs2_v;
}

void helper_csdebugcountprint(CPURISCVState *env) {
    CAPSLOCK_DEBUG_PRINT("CAPSLOCK DEBUG COUNTERS\n");
    int i;
    for(i = 0; i < 32; i ++) {
        CAPSLOCK_DEBUG_PRINT("counter[%d] = %lu\n", i, env->capslock_debug_counters[i]);
    }
}

inline static void insert_bounds(capboundsfat_t *dst, capboundsfat_t *src, int *cnt, capaddr_t addr) {
    for(int j = 0; j < CAP_MAX_PROVENANCE_N && src[j].rev_node != NULL;
            j ++) {
        int k;
        for(k = 0; k < *cnt && src[j].rev_node != dst[k].rev_node; k ++);
        if(*cnt < CAP_MAX_PROVENANCE_N && k == *cnt) {
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
            }
        }

    }
}

void helper_move_cap(CPURISCVState *env, uint64_t v, uint32_t rd_v, uint32_t rs1_v, uint32_t rs2_v) {
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

struct stackframe {
	unsigned long fp;
	unsigned long ra;
};

static inline int fp_is_valid(unsigned long fp, unsigned long sp)
{
	unsigned long low, high;

	low = sp + sizeof(struct stackframe);
	high = sp + 0x8000;

	return !(fp < low || fp > high || fp & 0x07);
}


// NOTE: this is only available for user-emulation mode
static void print_stack_trace(CPURISCVState *env) {
    uintptr_t fp = env->gpr[8].val.scalar;
    uintptr_t sp = env->gpr[xSP].val.scalar;
    uintptr_t pc = env->pc;
    while(1) {
        fprintf(stderr, "PC: %lx\n", pc);
        if(!fp_is_valid(fp, sp))
            break;
        sp = fp;
        struct stackframe frame;
        cpu_memory_rw_debug(env_cpu(env), fp - sizeof(struct stackframe), &frame, sizeof(struct stackframe), false);
        fp = frame.fp;
        pc = frame.ra;
    }
}
