#include <string.h>
#include <assert.h>
#include "cap_mem_map.h"

static inline bool addr_is_aligned(cap_mem_map_addr_t addr) {
    return (addr & 15) == 0;
}

static inline cap_mem_map_addr_t addr_round_down(cap_mem_map_addr_t addr) {
    return addr & ~(cap_mem_map_addr_t)15;
}

static inline cap_mem_map_addr_t addr_get_entry_base(cap_mem_map_addr_t addr) {
    return addr & ~(cap_mem_map_addr_t)4095;
}

static inline unsigned addr_get_entry_offset(cap_mem_map_addr_t addr) {
    return (unsigned)((addr & 4095) >> 4);
}

static inline void set_entry_at_offset(struct CapMemMapEntry *entry, unsigned offset) {
    unsigned idx = offset >> 6;
    unsigned bidx = offset & 63;
    entry->map[idx] |= (uint64_t)1 << bidx;
}

static inline void clear_entry_at_offset(struct CapMemMapEntry *entry, unsigned offset) {
    unsigned idx = offset >> 6;
    unsigned bidx = offset & 63;
    entry->map[idx] &= ~((uint64_t)1 << bidx);
}

static inline bool get_entry_at_offset(struct CapMemMapEntry *entry, unsigned offset) {
    unsigned idx = offset >> 6;
    unsigned bidx = offset & 63;
    return ((entry->map[idx] >> bidx) & 1) != 0;
}

static struct CapMemMapEntry* find_entry(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr) {
    cap_mem_map_addr_t base_addr = addr_get_entry_base(addr);
    int i;
    int n = cm_map->n;
    for(i = 0; i < n && cm_map->entries[i].addr != base_addr; i ++);
    if(i == n) {
        return NULL;
    }
    return &cm_map->entries[i];
}

static struct CapMemMapEntry* add_entry(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr) {
    assert(cm_map->n < CAP_MEM_MAP_ENTRY_N);
    struct CapMemMapEntry *entry = &cm_map->entries[cm_map->n++];
    memset(entry->map, 0, sizeof(entry->map));
    entry->addr = addr_get_entry_base(addr);
    return entry;
}

void cap_mem_map_add(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr) {
    if(addr_is_aligned(addr)) {
        struct CapMemMapEntry *entry = find_entry(cm_map, addr);
        if(!entry) {
            entry = add_entry(cm_map, addr);
        }
        unsigned offset = addr_get_entry_offset(addr);
        set_entry_at_offset(entry, offset);
    }
}

void cap_mem_map_remove(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr) {
    if(addr_is_aligned(addr)) {
        struct CapMemMapEntry *entry = find_entry(cm_map, addr);
        if(entry) {
            unsigned offset = addr_get_entry_offset(addr);
            clear_entry_at_offset(entry, offset);
        }
    }
}

void cap_mem_map_remove_range(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr, unsigned size) {
    cap_mem_map_addr_t start_addr = addr_round_down(addr);
    cap_mem_map_addr_t end_addr = addr_round_down(addr + size - 1);
    for(; start_addr <= end_addr; start_addr += 16) {
        cap_mem_map_remove(cm_map, start_addr);
    }
}

bool cap_mem_map_query(cap_mem_map_t *cm_map, cap_mem_map_addr_t addr) {
    if(addr_is_aligned(addr)) {
        struct CapMemMapEntry *entry = find_entry(cm_map, addr);
        if(entry) {
            unsigned offset = addr_get_entry_offset(addr);
            return get_entry_at_offset(entry, offset);
        } else {
            return false;
        }
    } else {
        return false;
    }
}

void cap_mem_map_clear(cap_mem_map_t *cm_map) {
    cm_map->n = 0;
}

void cap_mem_map_init(cap_mem_map_t *cm_map) {
    cm_map->n = 0;
}
