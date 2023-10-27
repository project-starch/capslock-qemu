#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "cap_compress.h"
#include "capstone_defs.h"

struct CapCompressed {
    uint64_t cursor;
    uint64_t other;
};

typedef struct CapCompressed cap_compressed_t;
STATIC_ASSERT(sizeof(cap_compressed_t) == 16, cap_compressed_size);

#define DEF_GET_FIELD(field, lo, hi) \
    static inline uint64_t field ## _get(cap_compressed_t *cc) { \
        return (cc->other >> lo) & (((uint64_t)1 << (hi - lo + 1)) - 1); \
    }

#define DEF_SET_FIELD(field, lo, hi) \
    static inline void field ## _set(cap_compressed_t *cc, uint64_t v) { \
        cc->other = (cc->other & ~((((uint64_t)1 << (hi - lo + 1)) - 1) << lo)) | \
                    (v << lo); \
    }

#define DEF_OTHER_FIELD(field, lo, hi) DEF_GET_FIELD(field, lo, hi) \
                                       DEF_SET_FIELD(field, lo, hi)


DEF_OTHER_FIELD(bE, 0, 2)
DEF_OTHER_FIELD(b, 3, 13)
DEF_OTHER_FIELD(tE, 14, 16)
DEF_OTHER_FIELD(t, 17, 25)
DEF_OTHER_FIELD(iE, 26, 26)
DEF_OTHER_FIELD(ty, 27, 29)
DEF_OTHER_FIELD(perms, 30, 32)
DEF_OTHER_FIELD(revnode_id, 33, 63)

void cap_compress(capfat_t *cap_fat, uint64_t *res_lo, uint64_t *res_hi) {
    uint64_t len = cap_fat->bounds.end - cap_fat->bounds.base;
    uint64_t leading_zeros;
    for(leading_zeros = 63; leading_zeros > 12 && ((len >> leading_zeros) & 1) == 0; -- leading_zeros);
    uint64_t E = leading_zeros - 12;
    uint64_t iE, B, T;

    if(E == 0 && ((len >> 12) & 1) == 0) {
        iE = 0;
        B = cap_fat->bounds.base & ((1 << 14) - 1);
        T = cap_fat->bounds.end & ((1 << 12) - 1);
    } else {
        iE = 1;
        B = (cap_fat->bounds.base >> E) & ~(uint64_t)7;
        T = (cap_fat->bounds.end >> E) & ~(uint64_t)7;
        if((cap_fat->bounds.end) & (((uint64_t)1 << (E + 3)) - 1)) {
            T += 8;
        }
        B |= E & 7;
        T |= (E >> 3) & 7;
    }

    cap_compressed_t cc;
    cc.cursor = cap_fat->bounds.cursor;
    bE_set(&cc, B & 7);
    b_set(&cc, (B >> 3) & ((1 << 11) - 1));
    tE_set(&cc, T & 7);
    t_set(&cc, (T >> 3) & ((1 << 9) - 1));
    iE_set(&cc, iE);
    perms_set(&cc, (uint64_t)cap_fat->perms);
    ty_set(&cc, (uint64_t)cap_fat->perms);
    revnode_id_set(&cc, 0);

    *res_lo = cc.cursor;
    *res_hi = cc.other;
}

void cap_uncompress(uint64_t lo, uint64_t hi, capfat_t *out) {
    cap_compressed_t cc = {lo, hi};
    uint64_t E;
    uint64_t B = b_get(&cc) << 3;
    uint64_t T = t_get(&cc) << 3;
    uint64_t b, t;
    bool carry_out, msb;

    if(iE_get(&cc)) {
        /* iE == 1 */
        E = (tE_get(&cc) << 3) | bE_get(&cc);
        msb = true;
    } else {
        /* iE == 0 */
        E = 0;
        T |= tE_get(&cc);
        B |= bE_get(&cc);
        msb = false;
    }
    carry_out = (T & 4095) < (B & 4095);
    T |= (((B >> 12) + carry_out + msb) & 3) << 12;
    b = (cc.cursor & ~((1 << (E + 14)) - 1)) | (B << E);
    t = (cc.cursor & ~((1 << (E + 14)) - 1)) | (T << E);

    uint64_t A3 = (cc.cursor >> (E + 11)) & 7;
    uint64_t B3 = (B >> 11) & 7;
    uint64_t T3 = (T >> 11) & 7;
    uint64_t R = (B3 - 1) & 7;

    if(A3 >= R && T3 < R)
        t += (uint64_t)1 << (E + 14);
    else if(A3 < R && T3 >= R)
        t -= (uint64_t)1 << (E + 14);
    
    if(A3 >= R && B3 < R)
        b += (uint64_t)1 << (E + 14);
    else if(A3 < R && B3 >= R)
        b -= (uint64_t)1 << (E + 14);

    out->async = CAP_ASYNC_SYNC;
    out->type = (captype_t)ty_get(&cc);
    out->perms = (capperms_t)perms_get(&cc);
    out->reg = 0;
    out->bounds.cursor = cc.cursor;
    out->bounds.base = b;
    out->bounds.end = t;
}

