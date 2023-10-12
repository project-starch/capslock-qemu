#ifndef CAP_H
#define CAP_H

#include <stdint.h>
#include <stdbool.h>

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
    CAP_TPYE_LIN        = 0x0,
    CAP_TYPE_NONLIN     = 0x1,
    CAP_TPYE_REV        = 0x2,
    CAP_TYPE_UNINIT     = 0x3,
    CAP_TPYE_SEALED     = 0x4,
    CAP_TPYE_SEALEDRET  = 0x5
};

typedef enum CapType captype_t;

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

#endif
