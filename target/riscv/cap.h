#ifndef CAP_H
#define CAP_H

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

typedef uint64_t capaddr_t;

enum CapPerms {
    CAP_PERMS_NA        = 0x0,
    CAP_PERMS_XO        = 0x1,
    CAP_PERMS_WO        = 0x2,
    CAP_PERMS_WX        = 0x3,
    CAP_PERMS_RO        = 0x4,
    CAP_PERMS_RX        = 0x5,
    CAP_PERMS_RW        = 0x6,
    CAP_PERMS_RWX       = 0x7
};

typedef enum CapPerms capperms_t;

enum CapType {
    CAP_TYPE_LIN        = 0x0,
    CAP_TYPE_NONLIN     = 0x1,
    CAP_TYPE_REV        = 0x2,
    CAP_TYPE_UNINIT     = 0x3,
    CAP_TYPE_SEALED     = 0x4,
    CAP_TYPE_SEALEDRET  = 0x5
};

#define CAP_SEALED_SIZE_MIN (16 * 33)

typedef enum CapType captype_t;

typedef uint16_t captype_mask_t;

#define DEF_CAP_TYPE_MASK(name) static const captype_mask_t CAP_TYPE_MASK_ ## name = 1 << (CAP_TYPE_ ## name);
DEF_CAP_TYPE_MASK(LIN)
DEF_CAP_TYPE_MASK(NONLIN)
DEF_CAP_TYPE_MASK(REV)
DEF_CAP_TYPE_MASK(UNINIT)
DEF_CAP_TYPE_MASK(SEALED)
DEF_CAP_TYPE_MASK(SEALEDRET)
#undef DEF_CAP_TYPE_MASK

enum CapAsync {
    CAP_ASYNC_SYNC      = 0x0,
    CAP_ASYNC_ECPT      = 0x1,
    CAP_ASYNC_INT       = 0x2
};

typedef enum CapAsync capasync_t;

typedef uint8_t reg_idx_t;

struct CapBoundsFat {
    capaddr_t cursor;
    capaddr_t base;
    capaddr_t end;
};

typedef struct CapBoundsFat capboundsfat_t;

// fat capability (used in CPU)
struct CapFat {
    capboundsfat_t bounds;
    capperms_t perms;
    captype_t type;
    capasync_t async; 
    reg_idx_t reg;
};

typedef struct CapFat capfat_t;

struct CapRegVal {
    union {
        capfat_t cap;
        capaddr_t scalar;
    } val;

    bool tag; // true: capability
};

typedef struct CapRegVal capregval_t;

static const capregval_t CAPREGVAL_NULL = {0};

static inline capaddr_t cap_size(capboundsfat_t* bounds) {
    return bounds->end - bounds->base;
}

static inline bool cap_aligned(capboundsfat_t* bounds, unsigned align) {
    return ((bounds->base >> align) << align) == bounds->base;
}

static inline bool cap_perms_allow(capperms_t perms, capperms_t access) {
    return (access & perms) == access;
}

static inline bool cap_in_bounds(capboundsfat_t* bounds, capaddr_t base, capaddr_t size) {
    return bounds->base <= base && base + size <= bounds->end;
}

bool cap_allow_access(capfat_t* cap, capaddr_t base, capaddr_t size, capperms_t access);

static inline bool capreg_allow_access(capregval_t* capreg, capaddr_t base, capaddr_t size, capperms_t access) {
    return capreg->tag && cap_allow_access(&capreg->val.cap, base, size, access);
}

static inline bool captype_is_copyable(captype_t ty) {
    return ty == CAP_TYPE_NONLIN;
}

static inline void capregval_set_scalar(capregval_t* capreg, capaddr_t v) {
    capreg->tag = false;
    capreg->val.scalar = v;
}

static inline void capregval_set_cap(capregval_t* capreg, capfat_t* cap) {
    capreg->tag = true;
    capreg->val.cap = *cap;
}

static inline void cap_set_capregval(capfat_t* cap, capregval_t* capreg) {
    assert(capreg->tag);
    *cap = capreg->val.cap;
}

static inline bool cap_type_in_mask(capfat_t* cap, captype_mask_t mask) {
    return ((mask >> cap->type) & 1) != 0;
}

#endif
