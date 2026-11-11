#include "chacha20.h"
#include "elf_utils.h"
#include "lz4.h"
#include "pe_utils.h"
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

/* Fill buf with n cryptographically random bytes from /dev/urandom. */
static int fill_random(void *buf, size_t n)
{
	const int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0)
		return (perror("/dev/urandom"), -1);
	if (full_read(fd, buf, n))
		return (perror("/dev/urandom read"), close(fd), -1);
	close(fd);
	return (0);
}

static int gen_key(t_file *f, const uint8_t *user_key)
{
	if (user_key)
		memcpy(f->key, user_key, sizeof(f->key));
	else if (fill_random(f->key, sizeof(f->key)))
		return (-1);
	if (fill_random(f->nonce, sizeof(f->nonce)))
		return (-1);
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
 * class-agnostic key/compress/encrypt steps are shared. `user_key` is the
 * 32-byte key parsed from -k, or NULL to generate one at random. */
static int pack(t_file *f, const t_file_ops *ops, const uint8_t *user_key)
{
	if (ops->validate(f) || gen_key(f, user_key) || ops->find_region(f)
		|| compress_encrypt(f) || ops->build_output(f))
		return (-1);
	return (0);
}

/* Decode one hex digit, or -1 if it is not one. */
static int hex_val(int c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

static int parse_hex_key(const char *s, uint8_t out[32])
{
	if (strlen(s) != 64)
		return (fprintf(stderr,
						"key must be exactly 64 hex digits (256-bit)\n"),
				-1);
	for (int i = 0; i < 32; i++)
	{
		const int hi = hex_val((unsigned char)s[2 * i]);
		const int lo = hex_val((unsigned char)s[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return (fprintf(stderr, "key contains a non-hex character\n"), -1);
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return (0);
}

/* mmap the input read-only and record its size. Format detection (ELF vs PE)
 * is the caller's job */
static int map_file(const char *filename, t_file *f)
{
	struct stat st;
	const int	fd = open(filename, O_RDONLY);

	if (fd < 0 || fstat(fd, &st) < 0)
		return (perror("can't open file"), -1);
	if (st.st_size <= 0)
		return (fprintf(stderr, "file is empty\n"), close(fd), -1);
	f->data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (f->data == MAP_FAILED)
		return (perror("couldn't mmap"), -1);
	f->size = st.st_size;
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

/* Parse argv into the input path and optional -k key. Returns 0 on success, or
 * 1 after printing usage. On success *keyarg points at the raw hex key or NULL.
 */
static int parse_args(int		   argc,
					  char		  *argv[],
					  const char **path,
					  const char **keyarg,
					  int		  *anti)
{
	const char *usage = "usage: %s [-k <hex256>] [-a] <elf>\n";

	*path = NULL;
	*keyarg = NULL;
	*anti = 0;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-k") == 0)
		{
			if (++i >= argc)
				return (fprintf(stderr, usage, argv[0]), 1);
			*keyarg = argv[i];
		}
		else if (strcmp(argv[i], "-a") == 0)
			*anti = 1;
		else if (!*path)
			*path = argv[i];
		else
			return (fprintf(stderr, usage, argv[0]), 1);
	}
	if (!*path)
		return (fprintf(stderr, usage, argv[0]), 1);
	return (0);
}

/* Container-specific prep + hook table selection, keyed on the detected format.
 * Both PE (.exe) and ELF share the pack pipeline; only the entries here differ,
 * so main's one real branch is picking which pair to use. */
static void select_format(t_file *f,
						  int (**prepare)(t_file *),
						  const t_file_ops *(**select)(const t_file *))
{
	if (pe_detect(f->data, f->size))
	{
		*prepare = pe_prepare;
		*select = pe_select_ops;
	}
	else
	{
		*prepare = elf_prepare;
		*select = elf_select_ops;
	}
}

/* The whole packing run once the input is mapped: detect the format, run the
 * shared checks (self-overwrite, already-packed) through the hook table, pack,
 * and write woody. Frees the owned buffers; the caller still owns the mapping.
 * Returns 0 on success, -1 on any failure. */
static int process(t_file *f, const char *path, const uint8_t *user_key)
{
	int (*prepare)(t_file *);
	const t_file_ops *(*select)(const t_file *);
	const t_file_ops *ops;
	int				  rc;

	select_format(f, &prepare, &select);
	if (prepare(f))
		return (-1);
	if (same_file(path, "woody"))
		return (fprintf(stderr, "input and output (woody) are the same file\n"),
				-1);
	ops = select(f);
	if (!ops)
		return (fprintf(stderr, "unsupported binary (opposite-endian ELF)\n"),
				-1);
	if (ops->is_packed(f))
		return (fprintf(stderr, "input is already packed\n"), -1);
	rc = pack(f, ops, user_key);
	if (rc == 0)
		rc = write_woody(f);
	free(f->blob);
	free(f->out);
	return (rc);
}

int main(int argc, char *argv[])
{
	t_file		f = {0};
	const char *path;
	const char *keyarg;
	uint8_t		user_key[32];
	int			anti;
	int			rc;

	if (parse_args(argc, argv, &path, &keyarg, &anti))
		return (1);
	if (keyarg && parse_hex_key(keyarg, user_key))
		return (1);
	if (map_file(path, &f))
		return (1);
	f.anti_debug = anti;
	rc = process(&f, path, keyarg ? user_key : NULL);
	munmap(f.data, f.size);
	return (rc ? 1 : 0);
}
