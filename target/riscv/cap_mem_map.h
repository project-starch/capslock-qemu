#ifndef _CAP_MEM_MAP_H_
#define _CAP_MEM_MAP_H_

#include <stdbool.h>
#include <stdint.h>
#include "cap.h"

#define CAP_MEM_MAP_ENTRY_N 512

typedef uint64_t cap_mem_map_addr_t;

/* Data structure that maintains which memory locations (paddr) */

struct CapMemMapEntry {
    cap_mem_map_addr_t addr;
    uint64_t map[8]; // covers 4 * 64 * 16 = 4096 bytes
    capboundsfat_t bounds[8 * 64]; // we hack this to prevent precision loss for now
};

struct CapMemMap {
    struct CapMemMapEntry entries[CAP_MEM_MAP_ENTRY_N];
    int n;
};

typedef struct CapMemMap cap_mem_map_t;

void cap_mem_map_add(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, capboundsfat_t *bounds);
void cap_mem_map_remove(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr);
void cap_mem_map_remove_range(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, unsigned size);
bool cap_mem_map_query(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, capboundsfat_t *bounds_out);
void cap_mem_map_clear(cap_mem_map_t *cm_map);
void cap_mem_map_init(cap_mem_map_t *cm_map);

#endif
