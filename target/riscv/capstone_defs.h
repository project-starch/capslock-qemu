#ifndef _CAPSTONE_DEFS_H_
#define _CAPSTONE_DEFS_H_

// #define CAPSTONE_DEBUG_INFO_EN

#define CAPSTONE_DEBUG_PRINT(fmt, ...) fprintf(stderr, "[CAPSTONE] " fmt, ##__VA_ARGS__)
#ifdef CAPSTONE_DEBUG_INFO_EN
#define CAPSTONE_DEBUG_INFO(fmt, ...) fprintf(stderr, "[CAPSTONE] " fmt, ##__VA_ARGS__)
#else
#define CAPSTONE_DEBUG_INFO(fmt, ...) {}
#endif

#define STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(COND)?1:-1]

enum CapstoneCCSRId {
    CAPSTONE_CCSR_CTVEC = 0x0,
    CAPSTONE_CCSR_CIH = 0x1,
    CAPSTONE_CCSR_CEPC = 0x2,
    CAPSTONE_CCSR_RESERVED = 0x3,
    CAPSTONE_CCSR_CSCRATCH = 0x4,
};

typedef enum CapstoneCCSRId capstone_ccsr_id_t;


#define CAPSTONE_IRQ_EXT   0x0
#define CAPSTONE_IRQ_TIMER 0x1
#define CAPSTONE_IRQ_SOFT  0x2
#define CAPSTONE_IRQ_MX    CAPSTONE_IRQ_SOFT
#define CAPSTONE_CCSR_CPMP_PAT  0x10
#define CAPSTONE_CCSR_CPMP_MASK 0xfff0
#define CAPSTONE_CCSR_CPMP_IND_MASK 0xf

#define CAPSTONE_CIS_PENDING_MASK    0x15

#endif
