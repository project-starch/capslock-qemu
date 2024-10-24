#include <string.h>
#include <assert.h>
#include <glib.h>
#include "cap_mem_map.h"
#include "cap_rev_tree.h"
#include <stdio.h>

#define MEM_CAP_SIZE 8 // size of a capability in memory in bytes
#define MEM_CAP_SIZE_LOG 3

cap_mem_map_t cm_map;

struct CapMemMap {
    GHashTable *tbl;
    cap_rev_tree_t *rev_tree;
};

static inline bool addr_is_aligned(cap_mem_map_addr_t addr) {
    return (addr & (MEM_CAP_SIZE - 1)) == 0;
}

static inline cap_mem_map_addr_t addr_round_down(cap_mem_map_addr_t addr) {
    return addr & ~(cap_mem_map_addr_t)(MEM_CAP_SIZE - 1);
}

#define MEM_CAP_MAP_BUF_N 65536
static capfat_t entry_buf[MEM_CAP_MAP_BUF_N];
static capfat_t *entry_free[MEM_CAP_MAP_BUF_N];
static int entry_free_n;

static inline capfat_t *alloc_entry(void) {
    if (entry_free_n > 0) {
        -- entry_free_n;
        return entry_free[entry_free_n];
    } else {
        return (capfat_t*)malloc(sizeof(capfat_t));
    }
}

static inline void free_entry(capfat_t *entry) {
    if (entry >= entry_buf && entry < entry_buf + MEM_CAP_MAP_BUF_N) {
        assert(entry_free_n < MEM_CAP_MAP_BUF_N);
        entry_free[entry_free_n ++] = entry;
    } else {
        free(entry);
    }
}

void cap_mem_map_add(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, capfat_t *cap) {
    if(addr_is_aligned(addr)) {
        capfat_t *t = g_hash_table_lookup(cm_map->tbl, (gpointer)addr);
        if (t) {
            cap_rev_tree_update_refcount(cm_map->rev_tree, t->rev_node_id, -1);
        } else {
            t = alloc_entry();
        }
        *t = *cap;
        g_hash_table_insert(cm_map->tbl, (gpointer)addr, t);
        cap_rev_tree_update_refcount(cm_map->rev_tree, t->rev_node_id, 1);
    }
}

void cap_mem_map_remove(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr) {
    addr = addr_round_down(addr);
    capfat_t *r = g_hash_table_lookup(cm_map->tbl, (gpointer)addr);
    if (r) {
        cap_rev_tree_update_refcount(cm_map->rev_tree, r->rev_node_id, -1);
        free_entry(r);
        g_hash_table_remove(cm_map->tbl, (gpointer)addr);
    }
}

void cap_mem_map_remove_range(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, unsigned size) {
    cap_mem_map_addr_t start_addr = addr_round_down(addr);
    cap_mem_map_addr_t end_addr = addr_round_down(addr + size - 1);
    for(; start_addr <= end_addr; start_addr += MEM_CAP_SIZE) {
        cap_mem_map_remove(cm_map, start_addr);
    }
}

bool cap_mem_map_query(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, capfat_t *cap_out) {
    if(addr_is_aligned(addr)) {
        capfat_t *r = g_hash_table_lookup(cm_map->tbl, (gpointer)addr);
        if (r) {
            if (cap_out)
                *cap_out = *r;
            return true;
        }
    }
    return false;
}

void cap_mem_map_clear(cap_mem_map_t *cm_map) {
    g_hash_table_destroy(cm_map->tbl);
}

void cap_mem_map_init(cap_mem_map_t *cm_map, cap_rev_tree_t *rev_tree) {
    for(int i = 0; i < CAP_MEM_MAP_ENTRY_N; i ++)
        entry_free[i] = entry_buf + i;
    entry_free_n = CAP_MEM_MAP_ENTRY_N;
    cm_map->tbl = g_hash_table_new(NULL, NULL);
    cm_map->rev_tree = rev_tree;
}
