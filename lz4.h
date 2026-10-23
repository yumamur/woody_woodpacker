#ifndef LZ4_H
#define LZ4_H

/* LZ4 is not one of the most size efficient compression algorithm, but it sure
 * is fast. Speed is more relevant for the scope of this project, since we want
 * to avoid delaying the execution of a packed binary. */

#include <stddef.h>
#include <stdint.h>

/* Worst-case output size for src of `n` bytes (incompressible input). */
size_t lz4_bound(size_t n);

/**
 * Compress `src[0..srclen]` into `dst`
 * @warning `dst` size >= lz4_bound(srclen), for a worst-case
 * @param src Data to compress
 * @param srclen Read length
 * @param dst Buffer to write the compressed data
 * @return Compressed size
 */
size_t lz4_compress(const uint8_t *src, size_t srclen, uint8_t *dst);

/* Decompress src[0..srclen) into dst (must hold dstcap >= original length).
 * Returns the decompressed length, or 0 on malformed input / overflow. */

/**
 * Decompress `src[0..srclen]` into `dst`
 * @param src Data to decompress
 * @param srclen Read length
 * @param dst Buffer to write the decompressed data
 * @param dstcap Buffer size
 * @return Decompressed size, or 0 on malformed input / overflow
 * @warning `dstcap` >= original length
 */
size_t lz4_decompress(const uint8_t *src, size_t srclen, uint8_t *dst,
					  size_t dstcap);

#endif
