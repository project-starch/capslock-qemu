#ifndef _CAP_MEM_MAP_H_
#define _CAP_MEM_MAP_H_

#include <stdbool.h>
#include <stdint.h>
#include "cap.h"
#include "cap_rev_tree.h"
#include <pthread.h>
#include <glib.h>

#define CAP_MEM_MAP_ENTRY_N 65536

typedef uint64_t cap_mem_map_addr_t;

/* Data structure that maintains which memory locations (paddr) */

struct CapMemMap;

typedef struct CapMemMap cap_mem_map_t;


extern cap_mem_map_t cm_map;
extern pthread_mutex_t cm_map_lock;

void cap_mem_map_add(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, capfat_t *cap);
void cap_mem_map_remove(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr);
void cap_mem_map_remove_range(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, unsigned size);
bool cap_mem_map_query(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, capfat_t *cap_out);
void cap_mem_map_clear(cap_mem_map_t *cm_map);
void cap_mem_map_init(cap_mem_map_t *cm_map, cap_rev_tree_t *rev_tree);

#endif
