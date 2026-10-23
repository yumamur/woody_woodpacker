/* no-PT_NOTE path. */
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc != 2)
		return (fprintf(stderr, "usage: %s <elf>\n", argv[0]), 1);
	FILE *f = fopen(argv[1], "r+b");
	if (!f)
		return (perror("fopen"), 1);
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	rewind(f);
	unsigned char *b = malloc(n);
	if (!b || fread(b, 1, n, f) != (size_t)n)
		return (fprintf(stderr, "read\n"), 1);
	Elf64_Ehdr *e = (Elf64_Ehdr *)b;
	Elf64_Phdr *p = (Elf64_Phdr *)(b + e->e_phoff);
	int			k = 0;
	for (int i = 0; i < e->e_phnum; i++)
		if (p[i].p_type == PT_NOTE)
		{
			p[i].p_type = PT_NULL;
			k++;
		}
	rewind(f);
	if (fwrite(b, 1, n, f) != (size_t)n)
		return (fprintf(stderr, "write\n"), 1);
	fclose(f);
	free(b);
	printf("neutralized %d PT_NOTE\n", k);
	return (0);
}
