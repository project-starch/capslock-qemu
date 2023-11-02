#ifndef _CAPSTONE_DEFS_H_
#define _CAPSTONE_DEFS_H_

#define CAPSTONE_DEBUG_PRINT(fmt, ...) fprintf(stderr, "[CAPSTONE] " fmt, ##__VA_ARGS__)
#define STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(COND)?1:-1]

enum CapstoneCCSRId {
    CAPSTONE_CCSR_CTVEC = 0x0,
    CAPSTONE_CCSR_CIH = 0x1,
    CAPSTONE_CCSR_CEPC = 0x2,
    CAPSTONE_CCSR_CMMU = 0x3,
    CAPSTONE_CCSR_CSCRATCH = 0x4
};

typedef enum CapstoneCCSRId capstone_ccsr_id_t;

#endif
