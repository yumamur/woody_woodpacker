/* Unit test for chacha20.c
 * Known-answer against RFC 8439 2.3.2, plus an encrypt/decrypt round-trip */
#include "../chacha20.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
	int ok = 1;

	/* key = 0..31, nonce = 00000009 0000004a 00000000, counter = 1
	 * The keystream = chacha20_xor over a zero buffer.
	 * its first 16 bytes are a published test vector. */
	uint8_t key[32];
	for (int i = 0; i < 32; i++)
		key[i] = (uint8_t)i;
	uint8_t nonce[12] = {0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0};
	uint8_t buf[64] = {0};
	chacha20_xor(key, nonce, 1, buf, sizeof(buf));
	const uint8_t want[16] = {0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
							  0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4};
	int kat = memcmp(buf, want, 16) == 0;
	printf("  RFC 8439 2.3.2 keystream : %s\n", kat ? "ok" : "FAIL");
	ok &= kat;

	/* round-trip: the same call encrypts and decrypts */
	uint8_t msg[333];
	uint8_t copy[333];
	for (size_t i = 0; i < sizeof(msg); i++)
		msg[i] = copy[i] = (uint8_t)(i * 7 + 3);
	chacha20_xor(key, nonce, 0, msg, sizeof(msg));
	int changed = memcmp(msg, copy, sizeof(msg)) != 0;
	chacha20_xor(key, nonce, 0, msg, sizeof(msg));
	int restored = memcmp(msg, copy, sizeof(msg)) == 0;
	printf("  encrypt changes data     : %s\n", changed ? "ok" : "FAIL");
	printf("  decrypt restores data    : %s\n", restored ? "ok" : "FAIL");
	ok &= changed && restored;

	printf("%s\n", ok ? "CHACHA PASS" : "CHACHA FAIL");
	return (!ok);
}
