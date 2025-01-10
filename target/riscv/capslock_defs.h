#ifndef _CAPSLOCK_DEFS_H_
#define _CAPSLOCK_DEFS_H_

// #define CAPSLOCK_DEBUG_INFO_EN

#define CAPSLOCK_DEBUG_PRINT(fmt, ...) fprintf(stderr, "[CAPSLOCK] " fmt, ##__VA_ARGS__)
#ifdef CAPSLOCK_DEBUG_INFO_EN
#define CAPSLOCK_DEBUG_INFO(fmt, ...) fprintf(stderr, "[CAPSLOCK] " fmt, ##__VA_ARGS__)
#else
#define CAPSLOCK_DEBUG_INFO(fmt, ...) {}
#endif

#define STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(COND)?1:-1]

enum CapsLockCCSRId {
    CAPSLOCK_CCSR_CTVEC = 0x0,
    CAPSLOCK_CCSR_CIH = 0x1,
    CAPSLOCK_CCSR_CEPC = 0x2,
    CAPSLOCK_CCSR_RESERVED = 0x3,
    CAPSLOCK_CCSR_CSCRATCH = 0x4,
};

typedef enum CapsLockCCSRId capslock_ccsr_id_t;


#define CAPSLOCK_IRQ_EXT   0x0
#define CAPSLOCK_IRQ_TIMER 0x1
#define CAPSLOCK_IRQ_SOFT  0x2
#define CAPSLOCK_IRQ_MX    CAPSLOCK_IRQ_SOFT
#define CAPSLOCK_CCSR_CPMP_PAT  0x10
#define CAPSLOCK_CCSR_CPMP_MASK 0xfff0
#define CAPSLOCK_CCSR_CPMP_IND_MASK 0xf

#define CAPSLOCK_CIS_PENDING_MASK    0x15

#endif
