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

static inline void pc_redirect_to_cap(CPURISCVState *env, capfat_t* cap) {
    env->pc_cap = *cap;
    env->pc = cap->bounds.cursor;
}

static inline void pc_redirect_to_addr(CPURISCVState *env, uint64_t addr) {
    env->pc = addr;
}

static inline void pc_redirect_to_capregval(CPURISCVState *env, capregval_t* v) {
    if(v->tag) {
        pc_redirect_to_cap(env, &v->val.cap);
    } else {
        pc_redirect_to_addr(env, v->val.scalar);
    }
}

enum domain_scoped_swap_mode {
    DOM_SCOPED_SWAP_INOUT, /* domain-scoped in and out */
    DOM_SCOPED_SWAP_IN, /* domain-scoped in, C-effective out */
    DOM_SCOPED_SWAP_OUT /* C-effective in, domain-scoped out */
};

void swap_domain_scoped_regs(AddressSpace *as, CPURISCVState *env, hwaddr base_addr, hwaddr pc_cursor,
    enum domain_scoped_swap_mode mode);
void swap_c_effective_regs(AddressSpace *as, CPURISCVState *env, hwaddr base_addr, hwaddr pc_cursor);


#endif
