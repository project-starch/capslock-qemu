#ifndef _CAPSTONE_DEFS_H_
#define _CAPSTONE_DEFS_H_

#define CAPSTONE_DEBUG_PRINT(fmt, ...) fprintf(stderr, "[CAPSTONE] " fmt, ##__VA_ARGS__)
#define STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(COND)?1:-1]

#endif
