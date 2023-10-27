#ifndef _CAP_COMPRESS_H_
#define _CAP_COMPRESS_H_

#include <stdint.h>
#include "cap.h"

void cap_compress(capfat_t *cap_fat, uint64_t *res_lo, uint64_t *res_hi);
void cap_uncompress(uint64_t lo, uint64_t hi, capfat_t *out);

#endif
