/* does some LZ4 round-trips, then checks the output is byte-identical. */
#include "../lz4.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int roundtrip(const char *name, const uint8_t *data, size_t n)
{
	uint8_t *c = malloc(lz4_bound(n) + 1);
	uint8_t *d = malloc(n + 16);
	size_t	 cl = lz4_compress(data, n, c);
	size_t	 dl = lz4_decompress(c, cl, d, n + 16);
	int		 ok = (dl == n) && (n == 0 || memcmp(d, data, n) == 0);

	printf("  %-16s in=%8zu comp=%8zu out=%8zu  %s\n", name, n, cl, dl,
		   ok ? "ok" : "FAIL");
	free(c);
	free(d);
	return (ok);
}

static uint8_t *slurp(const char *p, size_t *n)
{
	int fd = open(p, O_RDONLY);

	if (fd < 0)
		return (NULL);
	off_t sz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	uint8_t *b = malloc(sz);
	if (read(fd, b, sz) != sz)
		return (close(fd), free(b), NULL);
	close(fd);
	*n = (size_t)sz;
	return (b);
}

int main(void)
{
	int ok = 1;

	printf("lz4 round-trip:\n");
	size_t	 n1 = 100000;
	uint8_t *rep = malloc(n1);
	for (size_t i = 0; i < n1; i++)
		rep[i] = "ABCD"[i % 4];
	ok &= roundtrip("repetitive", rep, n1);
	free(rep);

	size_t	 n2 = 100000;
	uint8_t *rnd = malloc(n2);
	srand(1234);
	for (size_t i = 0; i < n2; i++)
		rnd[i] = (uint8_t)rand();
	ok &= roundtrip("incompressible", rnd, n2);
	free(rnd);

	uint8_t tiny[5] = {1, 2, 3, 4, 5};
	ok &= roundtrip("tiny", tiny, 5);
	ok &= roundtrip("empty", tiny, 0);

	/* real binaries */
	const char *files[] = {"/bin/ls", "/bin/sh", "woody_woodpacker", NULL};
	for (int i = 0; files[i]; i++)
	{
		size_t	 n;
		uint8_t *b = slurp(files[i], &n);
		if (b)
		{
			ok &= roundtrip(files[i], b, n);
			free(b);
		}
	}
	printf("%s\n", ok ? "LZ4 PASS" : "LZ4 FAIL");
	return (!ok);
}
