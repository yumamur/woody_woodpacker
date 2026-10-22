#include "chacha20.h"
#include "elf_utils.h"
#include "stub.h"
#include <string.h>
#include <sys/mman.h>

int in_bounds(t_file *f, uint64_t offset, uint64_t len)
{
	return (offset < f->size && offset + len <= f->size);
}

/* read/write loops that tolerate short transfers. */
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

static int full_pwrite(int fd, const void *buf, size_t n, off_t pos)
{
	size_t	off = 0;
	ssize_t w;

	while (off < n)
	{
		w = pwrite(fd, (const char *)buf + off, n - off, pos + (off_t)off);
		if (w <= 0)
			return (-1);
		off += (size_t)w;
	}
	return (0);
}

/**
 * Copy the stub into the reserved slot and fill its parameter block:
 * 1- The jump-back delta
 * 2- the region to decrypt (start delta + length)
 * 3- The ChaCha key/nonce.
 * The region starts at the original entry, so its start delta is the same as
 * the jump-back delta.
 */
static int fill_stub(t_file *f, uint64_t stub_vaddr)
{
	const Elf64_Ehdr *oeh = (const Elf64_Ehdr *)f->data;
	const uint64_t	  magic = STUB_PARAMS_MAGIC;
	const int64_t	  delta = (int64_t)oeh->e_entry - (int64_t)stub_vaddr;
	uint8_t			 *slot = f->append;
	uint8_t			 *p;
	size_t			  i;

	if (stub_bin_len > STUB_SIZE)
		return (fprintf(stderr,
						"stub (%u) exceeds slot (%lu)\n",
						stub_bin_len,
						(unsigned long)STUB_SIZE),
				-1);
	memcpy(slot, stub_bin, stub_bin_len);
	for (i = 0; i + sizeof(magic) <= stub_bin_len; i++)
		if (memcmp(slot + i, &magic, sizeof(magic)) == 0)
			break;
	if (i + sizeof(magic) > stub_bin_len)
		return (fprintf(stderr, "stub params magic not found\n"), -1);
	p = slot + i;
	memcpy(p + STUB_P_ENTRY_DELTA, &delta, sizeof(delta));
	memcpy(p + STUB_P_REGION_DELTA, &delta, sizeof(delta));
	memcpy(p + STUB_P_REGION_LEN, &f->enc_len, sizeof(f->enc_len));
	memcpy(p + STUB_P_KEY, f->key, sizeof(f->key));
	memcpy(p + STUB_P_NONCE, f->nonce, sizeof(f->nonce));
	return (0);
}

static void add_patch(t_file *f, size_t off, const void *buf, size_t len)
{
	t_patch *p = &f->patch[f->npatch++];

	p->off = off;
	p->len = len;
	memcpy(p->buf, buf, len);
}

static int find_phnote_index64(t_file *f)
{
	const Elf64_Ehdr *eh = (Elf64_Ehdr *)f->data;
	const Elf64_Phdr *ph = (Elf64_Phdr *)(f->data + eh->e_phoff);

	for (Elf64_Half i = 0; i < eh->e_phnum; i++)
		if (ph[i].p_type == PT_NOTE)
			return (i);
	return (-1);
}

/* The PT_LOAD with PF_X (executable) flag contains the original entry point. */
static const Elf64_Phdr *find_exec_load64(t_file *f, uint64_t entry)
{
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f->data;
	const Elf64_Phdr *ph = (const Elf64_Phdr *)(f->data + eh->e_phoff);

	for (Elf64_Half i = 0; i < eh->e_phnum; i++)
		if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)
			&& entry >= ph[i].p_vaddr && entry < ph[i].p_vaddr + ph[i].p_filesz)
			return (&ph[i]);
	return (NULL);
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

/*
 * Encrypt from the original entry to the end of its executable
 * segment. Starting at the entry keeps us clear of the ELF header and
 * of anything the loader/ld.so consult before reaching us.
 */
static int encrypt_region64(t_file *f)
{
	const Elf64_Ehdr *oeh = (const Elf64_Ehdr *)f->data;
	const uint64_t	  entry = oeh->e_entry;
	const Elf64_Phdr *seg = find_exec_load64(f, entry);
	size_t			  seg_end;

	if (!seg)
		return (fprintf(stderr, "no executable segment for entry\n"), -1);
	f->enc_off = entry - seg->p_vaddr + seg->p_offset;
	seg_end = seg->p_offset + seg->p_filesz;
	if (f->enc_off >= seg_end
		|| !in_bounds(f, f->enc_off, seg_end - f->enc_off))
		return (fprintf(stderr, "bad code region\n"), -1);
	f->enc_len = seg_end - f->enc_off;
	f->enc = malloc(f->enc_len);
	if (!f->enc)
		return (perror("malloc"), -1);
	memcpy(f->enc, f->data + f->enc_off, f->enc_len);
	chacha20_xor(f->key, f->nonce, 0, f->enc, f->enc_len);
	fprintf(stderr,
			"[woody] encrypt file[%#zx..%#zx) len=%#zx\n",
			f->enc_off,
			seg_end,
			f->enc_len);
	return (0);
}

static int inject_note64(t_file	 *f,
						 int	  note,
						 size_t	  stub_off,
						 uint64_t stub_vaddr)
{
	const Elf64_Ehdr *oeh = (const Elf64_Ehdr *)f->data;
	Elf64_Ehdr		  eh = *oeh;
	const size_t	  ph_off = oeh->e_phoff + (size_t)note * sizeof(Elf64_Phdr);
	Elf64_Phdr		  ph = *(const Elf64_Phdr *)(f->data + ph_off);

	f->append = calloc(1, STUB_SIZE);
	if (!f->append)
		return (perror("calloc"), -1);
	f->append_len = STUB_SIZE;
	if (fill_stub(f, stub_vaddr))
		return (-1);
	ph.p_type = PT_LOAD;
	ph.p_flags = PF_R | PF_X;
	ph.p_offset = stub_off;
	ph.p_vaddr = stub_vaddr;
	ph.p_paddr = stub_vaddr;
	ph.p_filesz = STUB_SIZE;
	ph.p_memsz = STUB_SIZE;
	ph.p_align = PAGE;
	eh.e_entry = stub_vaddr;
	add_patch(f, 0, &eh, sizeof(eh));
	add_patch(f, ph_off, &ph, sizeof(ph));
	fprintf(stderr, "[woody] PT_NOTE hijack @ phdr[%d]\n", note);
	return (0);
}

static int inject_newphdr64(t_file *f, size_t stub_off, uint64_t stub_vaddr)
{
	const Elf64_Ehdr *oeh = (const Elf64_Ehdr *)f->data;
	Elf64_Ehdr		  eh = *oeh;
	const Elf64_Half  phnum = oeh->e_phnum;
	const size_t	  phtab_off = stub_off + STUB_SIZE;
	const size_t	  newtab_bytes = (size_t)(phnum + 1) * sizeof(Elf64_Phdr);
	const size_t	  seg_size = STUB_SIZE + newtab_bytes;
	const uint64_t	  phtab_vaddr = stub_vaddr + STUB_SIZE;

	f->append = calloc(1, seg_size);
	if (!f->append)
		return (perror("calloc"), -1);
	f->append_len = seg_size;
	if (fill_stub(f, stub_vaddr))
		return (-1);
	Elf64_Phdr *nt = (Elf64_Phdr *)(f->append + STUB_SIZE);
	memcpy(nt, f->data + oeh->e_phoff, (size_t)phnum * sizeof(Elf64_Phdr));
	for (Elf64_Half i = 0; i < phnum; i++)
		if (nt[i].p_type == PT_PHDR)
		{
			nt[i].p_offset = phtab_off;
			nt[i].p_vaddr = phtab_vaddr;
			nt[i].p_paddr = phtab_vaddr;
			nt[i].p_filesz = newtab_bytes;
			nt[i].p_memsz = newtab_bytes;
		}
	Elf64_Phdr *nl = &nt[phnum];
	nl->p_type = PT_LOAD;
	nl->p_flags = PF_R | PF_X;
	nl->p_offset = stub_off;
	nl->p_vaddr = stub_vaddr;
	nl->p_paddr = stub_vaddr;
	nl->p_filesz = seg_size;
	nl->p_memsz = seg_size;
	nl->p_align = PAGE;
	eh.e_phoff = phtab_off;
	eh.e_phnum = phnum + 1;
	eh.e_entry = stub_vaddr;
	add_patch(f, 0, &eh, sizeof(eh));
	fprintf(stderr,
			"[woody] new PT_LOAD, phdr table relocated to %#zx\n",
			phtab_off);
	return (0);
}

static int inject64(t_file *f)
{
	Elf64_Ehdr	  *eh = (Elf64_Ehdr *)f->data;
	const size_t   stub_off = f->size;
	const uint64_t stub_vaddr = STUB_VADDR_BASE + stub_off;
	int			   note;

	if (eh->e_phnum == 0 || eh->e_phentsize != sizeof(Elf64_Phdr)
		|| !in_bounds(f, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum))
		return (fprintf(stderr, "who makes these files?\n"), -1);
	if (gen_key(f) || encrypt_region64(f))
		return (-1);
	note = find_phnote_index64(f);
	// hijack a PT_NOTE entry into an R+X PT_LOAD
	if (note >= 0)
		return (inject_note64(f, note, stub_off, stub_vaddr));
	// no PT_NOTE to spare, append a new one
	return (inject_newphdr64(f, stub_off, stub_vaddr));
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

/**
 *	1. Create a copy of the file
 *  2. Append the stub
 *  3. Patch the headers
 */
int write_woody(t_file *f)
{
	const char *exec_name = "woody";
	int			fd = open(exec_name, O_CREAT | O_TRUNC | O_RDWR, 0755);

	if (fd == -1)
		return (perror("No can do"), -1);
	if (full_write(fd, f->data, f->size))
		return (perror("write"), close(fd), -1);
	if (f->append_len && full_write(fd, f->append, f->append_len))
		return (perror("write append"), close(fd), -1);
	for (int i = 0; i < f->npatch; i++)
		if (full_pwrite(fd,
						f->patch[i].buf,
						f->patch[i].len,
						(off_t)f->patch[i].off))
			return (perror("pwrite patch"), close(fd), -1);
	if (f->enc && full_pwrite(fd, f->enc, f->enc_len, (off_t)f->enc_off))
		return (perror("pwrite enc"), close(fd), -1);
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

/* Our products carry the stub's parameter-block magic in the clear, meaning
 * we already packed said file. So we refuse rather than onion packing. */
static int already_packed(const t_file *f)
{
	const uint64_t magic = STUB_PARAMS_MAGIC;

	if (f->size < sizeof(magic))
		return (0);
	for (size_t i = 0; i + sizeof(magic) <= f->size; i++)
		if (memcmp(f->data + i, &magic, sizeof(magic)) == 0)
			return (1);
	return (0);
}

int main(int argc, char *argv[])
{
	t_file f = {0};
	int	   rc;

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
	if (f.swap)
		rc = (fprintf(stderr, "big-endian ELF not supported\n"), -1);
	else if (f.is64)
		rc = inject64(&f);
	else
		rc = (fprintf(stderr, "32-bit injection not implemented yet\n"), -1);
	if (rc == 0)
		rc = write_woody(&f);
	free(f.append);
	free(f.enc);
	munmap(f.data, f.size);
	return (rc ? 1 : 0);
}
