#include "chacha20.h"
#include "elf_utils.h"
#include "lz4.h"
#include <string.h>
#include <sys/mman.h>

static int full_read(int fd, void *buf, size_t n)
{
	size_t	off = 0;
	ssize_t r;

	while (off < n)
	{
		r = read(fd, (char *)buf + off, n - off);
		if (r <= 0)
			return (-1);
		off += (size_t)r;
	}
	return (0);
}

static int full_write(int fd, const void *buf, size_t n)
{
	size_t	off = 0;
	ssize_t w;

	while (off < n)
	{
		w = write(fd, (const char *)buf + off, n - off);
		if (w <= 0)
			return (-1);
		off += (size_t)w;
	}
	return (0);
}

/* Random 256-bit key + 96-bit nonce from /dev/urandom. */
static int gen_key(t_file *f)
{
	const int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0)
		return (perror("/dev/urandom"), -1);
	if (full_read(fd, f->key, sizeof(f->key))
		|| full_read(fd, f->nonce, sizeof(f->nonce)))
		return (perror("/dev/urandom read"), close(fd), -1);
	close(fd);
	printf("key_value: ");
	for (size_t i = 0; i < sizeof(f->key); i++)
		printf("%02X", f->key[i]);
	printf("\n");
	fflush(stdout);
	return (0);
}

/* Compress the already-located code region, then ChaCha20-encrypt the
 * compressed bytes. Compression works best on low-entropy input, so the order
 * is compress -> encrypt. Class-agnostic: it works on the raw region bytes. */
static int compress_encrypt(t_file *f)
{
	uint8_t *comp = malloc(lz4_bound(f->region_len));

	if (!comp)
		return (perror("malloc"), -1);
	f->comp_len = lz4_compress(f->data + f->region_off, f->region_len, comp);
	if (f->comp_len == 0)
		return (fprintf(stderr, "compression failed\n"), free(comp), -1);
	chacha20_xor(f->key, f->nonce, 0, comp, f->comp_len);
	f->blob = comp;
	fprintf(stderr,
			"[woody] region file[%#zx..%#zx) L=%#zx -> comp=%#zx (%.1f%%)\n",
			f->region_off,
			f->region_off + f->region_len,
			f->region_len,
			f->comp_len,
			100.0 * (double)f->comp_len / (double)f->region_len);
	return (0);
}

/* The packing pipeline: the flavour-specific steps come from `ops`, the
 * class-agnostic key/compress/encrypt steps are shared. */
static int pack(t_file *f, const t_elf_ops *ops)
{
	if (ops->validate(f) || gen_key(f) || ops->find_region(f)
		|| compress_encrypt(f) || ops->build_output(f))
		return (-1);
	return (0);
}

static int get_valid_file(char *filename, t_file *f)
{
	struct stat	   st;
	const uint16_t one = 1;
	const int	   fd = open(filename, O_RDONLY);

	if (fd < 0 || fstat(fd, &st) < 0)
		return (perror("can't open file"), -1);
	if (st.st_size <= 0)
		return (fprintf(stderr, "file is empty\n"), close(fd), -1);
	f->data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (f->data == MAP_FAILED)
		return (perror("couldn't mmap"), -1);
	if (is_valid_elf(f->data, st.st_size) == 0)
		return (fprintf(stderr, "file is not valid elf\n"),
				munmap(f->data, st.st_size),
				-1);
	f->size = st.st_size;
	f->is64 = f->data[EI_CLASS] == ELFCLASS64;
	f->swap = (f->data[EI_DATA] == ELFDATA2LSB)
			  != (*(const uint8_t *)&one == 1);
	return (0);
}

int write_woody(t_file *f)
{
	const char *exec_name = "woody";
	int			fd = open(exec_name, O_CREAT | O_TRUNC | O_RDWR, 0755);

	if (fd == -1)
		return (perror("No can do"), -1);
	if (full_write(fd, f->out, f->out_len))
		return (perror("write"), close(fd), -1);
	close(fd);
	return (0);
}

/* Used to refuse overwriting the input with "woody" */
static int same_file(const char *a, const char *b)
{
	struct stat sa;
	struct stat sb;

	if (stat(a, &sa) != 0 || stat(b, &sb) != 0)
		return (0);
	return (sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino);
}

/* Our output carries a marker in its e_ident padding; if we see it, the file is
 * already packed and we refuse rather than onion-packing. O(1) check. */
static int already_packed(const t_file *f)
{
	return (f->size >= EI_NIDENT
			&& memcmp(f->data + WOODY_MARK_OFF, WOODY_MARK, WOODY_MARK_LEN) == 0);
}

int main(int argc, char *argv[])
{
	const t_elf_ops *ops;
	t_file			 f = {0};
	int				 rc;

	if (argc != 2)
		return (fprintf(stderr, "usage: %s <elf>\n", argv[0]), 1);
	if (get_valid_file(argv[1], &f))
		return (1);
	if (same_file(argv[1], "woody"))
		return (fprintf(stderr, "input and output (woody) are the same file\n"),
				munmap(f.data, f.size),
				1);
	if (already_packed(&f))
		return (fprintf(stderr,
						"input is already packed by woody_woodpacker\n"),
				munmap(f.data, f.size),
				1);
	ops = elf_select_ops(&f);
	if (!ops)
		rc = (fprintf(stderr,
					  "unsupported ELF class/endianness (32-bit and "
					  "big-endian are not implemented yet)\n"),
			  -1);
	else
		rc = pack(&f, ops);
	if (rc == 0)
		rc = write_woody(&f);
	free(f.blob);
	free(f.out);
	munmap(f.data, f.size);
	return (rc ? 1 : 0);
}
