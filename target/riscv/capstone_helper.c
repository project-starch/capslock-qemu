#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internals.h"
#include "pmu.h"
#include "exec/exec-all.h"
#include "instmap.h"
#include "tcg/tcg-op.h"
#include "trace.h"
#include "semihosting/common-semi.h"
#include "sysemu/cpu-timers.h"
#include "cpu_bits.h"
#include "cap.h"
#include "cap_compress.h"
#include "debug.h"
#include "tcg/oversized-guest.h"
#include "capstone_defs.h"
#include "capstone_helper.h"

void store_cap(AddressSpace *as, CPURISCVState *env, hwaddr addr, capfat_t *cap) {
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    uint64_t lo, hi;
    cap_compress(cap, &lo, &hi);
    address_space_stq(as, addr, lo, attrs, &res);
    address_space_stq(as, addr + 8, hi, attrs, &res);
    cap_mem_map_add(&env->cm_map, addr, &cap->bounds);
}

void load_capregval(AddressSpace *as, CPURISCVState *env, hwaddr addr, capregval_t *v) {
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    uint64_t lo, hi;
    capboundsfat_t bounds;
    if(cap_mem_map_query(&env->cm_map, addr, &bounds)) {
        lo = address_space_ldq(as, addr, attrs, &res);
        hi = address_space_ldq(as, addr + 8, attrs, &res);
        v->tag = true;
        cap_uncompress(lo, hi, &v->val.cap);
        memcpy(&v->val.cap.bounds, &bounds, sizeof(capboundsfat_t));
    } else {
        v->tag = false;
        v->val.scalar = address_space_ldq(as, addr, attrs, &res);
    }
}

void store_capregval(AddressSpace *as, CPURISCVState *env, hwaddr addr, capregval_t *v) {
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    uint64_t lo, hi;
    assert(!(addr & 15)); // must be aligned
    if(v->tag) {
        cap_compress(&v->val.cap, &lo, &hi);
        address_space_stq(as, addr, lo, attrs, &res);
        address_space_stq(as, addr + 8, hi, attrs, &res);
        cap_mem_map_add(&env->cm_map, addr, &v->val.cap.bounds);
    } else {
        address_space_stq(as, addr, v->val.scalar, attrs, &res);
        cap_mem_map_remove(&env->cm_map, addr);
    }
}

static inline void swap_int64(AddressSpace *as, CPURISCVState *env, hwaddr addr, uint64_t *v) {
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    assert(!(addr & 7));
    uint64_t tmp;
    tmp = address_space_ldq(as, addr, attrs, &res);
    address_space_stq(as, addr, *v, attrs, &res);
    *v = tmp;
}

static inline void swap_pc(AddressSpace *as, CPURISCVState *env, hwaddr addr, hwaddr pc_cursor) {
    capregval_t loaded_val;
    load_capregval(as, env, addr, &loaded_val);
    // doesn't have to be a capability
    // assert(loaded_val.tag);
    env->pc_cap.bounds.cursor = pc_cursor;
    store_cap(as, env, addr, &env->pc_cap);
    env->pc_cap = loaded_val.val.cap;
    env->pc = loaded_val.val.cap.bounds.cursor;
}

#define CAPSTONE_CAP_SIZE 16
#define CAPSTONE_INT64_SIZE 8

#define SWAP_CAP(x) do { swap_capregval(as, env, base_addr, &env->x); \
                    base_addr += CAPSTONE_CAP_SIZE; } while(0)
#define SWAP_INT64(x) do { swap_int64(as, env, base_addr, &env->x); \
                    base_addr += CAPSTONE_INT64_SIZE; } while(0)

void swap_domain_scoped_regs(AddressSpace *as, CPURISCVState *env, hwaddr base_addr, hwaddr pc_cursor,
        enum domain_scoped_swap_mode mode) {
    int i;

    // CAPSTONE_DEBUG_PRINT("Domain scoped regs swapping @ 0x%lx\n", base_addr);

    // swap PC
    swap_pc(as, env, base_addr, pc_cursor);
    base_addr += CAPSTONE_CAP_SIZE;

    // swap CCSRs
    SWAP_CAP(ctvec);
    SWAP_CAP(cscratch);

    // swap 64-bit CSRs

    // swap mstatus including the privilege level
    assert(!((env->mstatus >> 38) & 3)); // the bits are actually unused
    assert((env->mstatus >> 34) & 3);
    uint64_t mstatus_priv = env->mstatus | ((uint64_t)env->priv << 38);
    swap_int64(as, env, base_addr, &mstatus_priv);
    env->mstatus = mstatus_priv & ~((uint64_t)3 << 38);
    // CAPSTONE_DEBUG_PRINT("D %lu %lu %d\n", env->priv, (mstatus_priv >> 38) & 3, env->ctvec.tag);
    riscv_cpu_set_mode(env, (mstatus_priv >> 38) & 3);
    base_addr += CAPSTONE_INT64_SIZE;

    // swap 64-bit CSRs
    SWAP_INT64(mideleg);
    SWAP_INT64(medeleg);
    SWAP_INT64(mip);
    SWAP_INT64(mie);

    // TODO: handle differently based on mode
    SWAP_INT64(offsetmmu);
    SWAP_CAP(cmmu);
    SWAP_CAP(cepc);

    // swap GPRs
    for(i = 1; i < 32; i ++) {
        SWAP_CAP(gpr[i]);
    }

    SWAP_INT64(mcause);
    SWAP_INT64(mtval);
    SWAP_INT64(mtval2);
    SWAP_INT64(mtinst);
    SWAP_INT64(stvec);
    SWAP_INT64(scause);
    SWAP_INT64(stval);
    SWAP_INT64(sepc);
    SWAP_INT64(sscratch);
    SWAP_INT64(satp);

    // above is identical to C-scoped regs
    
    tlb_flush(env_cpu(env)); // because satp has been changed

    QEMU_IOTHREAD_LOCK_GUARD(); // TODO: is this the right place?
    riscv_cpu_check_interrupts(env);
}

void swap_c_effective_regs(AddressSpace *as, CPURISCVState *env, hwaddr base_addr, hwaddr pc_cursor) {
    // CAPSTONE_DEBUG_PRINT("C-effective regs swapping @ 0x%lx\n", base_addr);

    // swap PC
    swap_pc(as, env, base_addr, pc_cursor);
    base_addr += CAPSTONE_CAP_SIZE;

    // swap CCSRs
    SWAP_CAP(ctvec);
    SWAP_CAP(cscratch);
    
    assert(!((env->mstatus >> 38) & 3)); // the bits are actually unused
    assert((env->mstatus >> 34) & 3);
    uint64_t mstatus_priv = env->mstatus | ((uint64_t)env->priv << 38);
    swap_int64(as, env, base_addr, &mstatus_priv);
    env->mstatus = mstatus_priv & ~((uint64_t)3 << 38);
    // CAPSTONE_DEBUG_PRINT("C %lu %lu %d\n", env->priv, (mstatus_priv >> 38) & 3, env->ctvec.tag);
    // assert(!(env->priv == 3 && ((mstatus_priv >> 38) & 3) == 0 && !env->ctvec.tag));
    riscv_cpu_set_mode(env, (mstatus_priv >> 38) & 3);
    base_addr += CAPSTONE_INT64_SIZE;

    // swap 64-bit CSRs
    SWAP_INT64(mideleg);
    SWAP_INT64(medeleg);
    SWAP_INT64(mip);
    SWAP_INT64(mie);

    assert((env->mstatus >> 34) & 3);

    QEMU_IOTHREAD_LOCK_GUARD(); // TODO: is this the right place?
    riscv_cpu_check_interrupts(env);
}

#undef SWAP_INT64
#undef SWAP_CAP
