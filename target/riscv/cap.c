#include "cap.h"
#include "cap_rev_tree.h"

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

bool cap_bounds_collapse(capboundsfat_t *bounds, capaddr_t addr, capaddr_t size, bool *is_far_oob) {
    bool _is_far_oob = true;
    int i;
    for(i = 0; i < CAP_MAX_PROVENANCE_N; i ++) {
        if (bounds[i].rev_node_id != CAP_REV_NODE_ID_NULL &&
                cap_in_bounds(&bounds[i], addr, (capaddr_t)size))
            break;
        if (bounds[i].rev_node_id != CAP_REV_NODE_ID_NULL && cap_distance(&bounds[i], addr) < 0x10)
            _is_far_oob = false;
    }
    // if(i >= CAP_MAX_PROVENANCE_N && !_is_far_oob) {
    //     fprintf(stderr, "Oops %lx %lx\n", addr, (capaddr_t)size);
    //     for(int j = 0; j < CAP_MAX_PROVENANCE_N; j ++) {
    //         fprintf(stderr, "Bounds: %lx %lx %lx %d %d\n", bounds[j].base, bounds[j].end,
    //             cap_distance(&bounds[j], addr), bounds[j].rev_node_id != CAP_REV_NODE_ID_NULL,
    //             cap_in_bounds(&bounds[j], addr, (capaddr_t)size));
    //     }
    // }
    if(i < CAP_MAX_PROVENANCE_N) {
        bounds[0] = bounds[i];
        for(int j = 1; j < CAP_MAX_PROVENANCE_N; j ++)
            bounds[j].rev_node_id = CAP_REV_NODE_ID_NULL;
    } else
        for(int j = 0; j < CAP_MAX_PROVENANCE_N; j ++)
            bounds[j].rev_node_id = CAP_REV_NODE_ID_NULL;
    if(is_far_oob)
        *is_far_oob = _is_far_oob;
    return i < CAP_MAX_PROVENANCE_N;
}
