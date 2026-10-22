#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

/**
 * ChaCha20 (RFC 8439) keystream XOR. Encrypt and decrypt are the same call.
 * @param key 256-bit
 * @param nonce 12-bytes (3 word)
 * @param counter initial block counter.
 * @param data will be modified in-place
 * */
void chacha20_xor(const uint8_t key[32],
				  const uint8_t nonce[12],
				  uint32_t		counter,
				  uint8_t	   *data,
				  size_t		len);

#endif
