#include "cap.h"

#define MAX_CAPMAP_SIZE 4096

static capfat_t cap_map[MAX_CAPMAP_SIZE];
static bool cap_map_alloced[MAX_CAPMAP_SIZE];
static int cap_map_n;

capfat_t *cap_map_get(int idx) {
    assert (idx >= 0 && idx < cap_map_n && cap_map_alloced[idx]);
    return &cap_map[idx];
}

int cap_map_alloc(void) {
    if (cap_map_n < MAX_CAPMAP_SIZE) {
        cap_map_alloced[cap_map_n] = true;
        return cap_map_n ++;
    }
    int i;
    for(i = 0; i < cap_map_n && cap_map_alloced[i]; i ++);
    assert(i < cap_map_n && !cap_map_alloced[i]);
    cap_map_alloced[i] = true;
    return i;
}

void cap_map_free(int idx) {
    assert (idx >= 0 && idx < cap_map_n && cap_map_alloced[idx]);
    cap_map_alloced[idx] = false;
}

bool cap_allow_access(capfat_t* cap, capaddr_t base, capaddr_t size, capperms_t access) {
    return cap_in_bounds(&cap->bounds[0], base, size) && cap_perms_allow(cap->perms, access);
}

