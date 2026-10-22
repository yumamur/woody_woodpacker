#include "chacha20.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// clang-format off
#define QR(a, b, c, d)                            \
		a += b; d ^= a; d = ROTL32(d, 16);        \
		c += d; b ^= c; b = ROTL32(b, 12);        \
		a += b; d ^= a; d = ROTL32(d, 8);         \
		c += d; b ^= c; b = ROTL32(b, 7);
// clang-format on

static uint32_t le32(const uint8_t *p)
{
	return ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16
			| (uint32_t)p[3] << 24);
}

static void chacha20_block(const uint32_t in[16], uint32_t out[16])
{
	memcpy(out, in, 16 * sizeof(uint32_t));
	for (int i = 0; i < 10; i++)
	{
		QR(out[0], out[4], out[8], out[12]);
		QR(out[1], out[5], out[9], out[13]);
		QR(out[2], out[6], out[10], out[14]);
		QR(out[3], out[7], out[11], out[15]);
		QR(out[0], out[5], out[10], out[15]);
		QR(out[1], out[6], out[11], out[12]);
		QR(out[2], out[7], out[8], out[13]);
		QR(out[3], out[4], out[9], out[14]);
	}
	for (int i = 0; i < 16; i++)
		out[i] += in[i];
}

void chacha20_xor(const uint8_t key[32],
				  const uint8_t nonce[12],
				  uint32_t		counter,
				  uint8_t	   *data,
				  size_t		len)
{
	uint32_t	   st[16];
	uint32_t	   ks[16];
	const uint8_t *kb = (const uint8_t *)ks;
	size_t		   off = 0;

	st[0] = 0x61707865;
	st[1] = 0x3320646e;
	st[2] = 0x79622d32;
	st[3] = 0x6b206574;
	for (int i = 0; i < 8; i++)
		st[4 + i] = le32(key + 4 * i);
	st[12] = counter;
	for (int i = 0; i < 3; i++)
		st[13 + i] = le32(nonce + 4 * i);
	while (off < len)
	{
		chacha20_block(st, ks);
		size_t n = len - off < 64 ? len - off : 64;
		for (size_t i = 0; i < n; i++)
			data[off + i] ^= kb[i];
		off += n;
		st[12]++;
	}
}
