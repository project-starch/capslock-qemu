#ifndef _CAPSTONE_HELPER_H_
#define _CAPSTONE_HELPER_H_

void store_cap(AddressSpace *as, CPURISCVState *env, hwaddr addr, capfat_t *cap);

void load_capregval(AddressSpace *as, CPURISCVState *env, hwaddr addr, capregval_t *v);

void store_capregval(AddressSpace *as, CPURISCVState *env, hwaddr addr, capregval_t *v);

static inline void swap_capregval(AddressSpace *as, CPURISCVState *env, hwaddr addr, capregval_t *v) {
    capregval_t loaded_v;
    load_capregval(as, env, addr, &loaded_v);
    store_capregval(as, env, addr, v);
    *v = loaded_v;
}

#endif
