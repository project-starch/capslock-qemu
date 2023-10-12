#include "cap.h"

bool cap_allow_access(capfat_t* cap, capaddr_t base, capaddr_t size, capperms_t access) {
    return cap_in_bounds(&cap->bounds, base, size) && cap_perms_allow(cap->perms, access);
}

