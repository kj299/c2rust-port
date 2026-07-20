#ifndef ADLER32_H
#define ADLER32_H

#include <stddef.h>
#include <stdint.h>

/* Adler-32 checksum of `len` bytes at `data`. `data` may be NULL iff len == 0. */
uint32_t adler32(const uint8_t *data, size_t len);

#endif /* ADLER32_H */
