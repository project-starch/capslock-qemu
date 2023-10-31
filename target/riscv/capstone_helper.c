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
    cap_mem_map_add(&env->cm_map, addr);
}

void load_capregval(AddressSpace *as, CPURISCVState *env, hwaddr addr, capregval_t *v) {
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    uint64_t lo, hi;
    if(cap_mem_map_query(&env->cm_map, addr)) {
        lo = address_space_ldq(as, addr, attrs, &res);
        hi = address_space_ldq(as, addr + 8, attrs, &res);
        v->tag = true;
        cap_uncompress(lo, hi, &v->val.cap);
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
        cap_mem_map_add(&env->cm_map, addr);
    } else {
        address_space_stq(as, addr, v->val.scalar, attrs, &res);
        cap_mem_map_remove(&env->cm_map, addr);
    }
}
