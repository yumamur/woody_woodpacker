#include "lz4.h"
#include <stdlib.h>

#define MINMATCH 4
#define HASHLOG 16
#define HASHSZ (1 << HASHLOG)
#define MAX_OFFSET 65535

size_t lz4_bound(size_t n)
{
	/* literals-only worst case: one token per 255 bytes + the data + slack. */
	return (n + n / 255 + 16);
}

static uint32_t read32(const uint8_t *p)
{
	return ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16
			| (uint32_t)p[3] << 24);
}

static uint32_t hash32(uint32_t v)
{
	return ((v * 2654435761u) >> (32 - HASHLOG));
}

static uint8_t *emit_extra(uint8_t *op, size_t extra)
{
	while (extra >= 255)
	{
		*op++ = 255;
		extra -= 255;
	}
	*op++ = (uint8_t)extra;
	return (op);
}

static uint8_t *emit_seq(uint8_t *op, const uint8_t *lit, size_t litlen,
						 size_t mlen, uint32_t offset)
{
	uint8_t *token = op++;
	size_t	 ml = mlen ? mlen - MINMATCH : 0;

	*token = (uint8_t)((litlen >= 15 ? 15 : litlen) << 4)
			 | (uint8_t)(mlen ? (ml >= 15 ? 15 : ml) : 0);
	if (litlen >= 15)
		op = emit_extra(op, litlen - 15);
	for (size_t i = 0; i < litlen; i++)
		*op++ = lit[i];
	if (mlen)
	{
		*op++ = (uint8_t)(offset & 0xff);
		*op++ = (uint8_t)(offset >> 8);
		if (ml >= 15)
			op = emit_extra(op, ml - 15);
	}
	return (op);
}

size_t lz4_compress(const uint8_t *src, size_t srclen, uint8_t *dst)
{
	int	   *table;
	uint8_t *op = dst;
	size_t	ip = 0;
	size_t	anchor = 0;

	table = malloc(sizeof(int) * HASHSZ);
	if (!table)
		return (0);
	for (size_t i = 0; i < HASHSZ; i++)
		table[i] = -1;
	while (ip + MINMATCH <= srclen)
	{
		uint32_t seq = read32(src + ip);
		uint32_t h = hash32(seq);
		int		 ref = table[h];

		table[h] = (int)ip;
		if (ref >= 0 && (ip - (size_t)ref) <= MAX_OFFSET
			&& read32(src + ref) == seq)
		{
			size_t mlen = MINMATCH;
			size_t litlen = ip - anchor;

			while (ip + mlen < srclen && src[ip + mlen] == src[(size_t)ref + mlen])
				mlen++;
			op = emit_seq(op, src + anchor, litlen, mlen,
						  (uint32_t)(ip - (size_t)ref));
			ip += mlen;
			anchor = ip;
		}
		else
			ip++;
	}
	/* trailing literals as a final, match-less sequence */
	op = emit_seq(op, src + anchor, srclen - anchor, 0, 0);
	free(table);
	return ((size_t)(op - dst));
}

size_t lz4_decompress(const uint8_t *src, size_t srclen, uint8_t *dst,
					  size_t dstcap)
{
	size_t sp = 0;
	size_t dp = 0;

	while (sp < srclen)
	{
		uint8_t token = src[sp++];
		size_t	litlen = token >> 4;
		size_t	mlen;
		size_t	offset;

		if (litlen == 15)
		{
			uint8_t b;
			do
			{
				if (sp >= srclen)
					return (0);
				b = src[sp++];
				litlen += b;
			} while (b == 255);
		}
		if (sp + litlen > srclen || dp + litlen > dstcap)
			return (0);
		for (size_t i = 0; i < litlen; i++)
			dst[dp++] = src[sp++];
		if (sp >= srclen)
			break; /* final literals-only sequence */
		if (sp + 2 > srclen)
			return (0);
		offset = (size_t)src[sp] | (size_t)src[sp + 1] << 8;
		sp += 2;
		if (offset == 0 || offset > dp)
			return (0);
		mlen = token & 15;
		if (mlen == 15)
		{
			uint8_t b;
			do
			{
				if (sp >= srclen)
					return (0);
				b = src[sp++];
				mlen += b;
			} while (b == 255);
		}
		mlen += MINMATCH;
		if (dp + mlen > dstcap)
			return (0);
		for (size_t i = 0; i < mlen; i++, dp++)
			dst[dp] = dst[dp - offset];
	}
	return (dp);
}
