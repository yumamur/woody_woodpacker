#include "elf_utils.h"
#include "stub.h"
#include <string.h>
#include <sys/mman.h>

int in_bounds(t_file *f, uint64_t offset, uint64_t len)
{
	return (offset < f->size && offset + len <= f->size);
}

/**
 * Copy the stub into the reserved slot and patch its jump-back delta
 */
static int fill_stub(uint8_t *slot, uint64_t stub_vaddr, uint64_t orig_entry)
{
	const uint64_t marker = STUB_DELTA_PLACEHOLDER;
	const int64_t  delta = (int64_t)orig_entry - (int64_t)stub_vaddr;

	if (stub_bin_len > STUB_SIZE)
		return (fprintf(stderr,
						"stub (%u) exceeds slot (%lu)\n",
						stub_bin_len,
						(unsigned long)STUB_SIZE),
				-1);
	memcpy(slot, stub_bin, stub_bin_len);
	for (size_t i = 0; i + sizeof(marker) <= stub_bin_len; i++)
		if (memcmp(slot + i, &marker, sizeof(marker)) == 0)
			return (memcpy(slot + i, &delta, sizeof(delta)), 0);
	return (fprintf(stderr, "stub delta placeholder not found\n"), -1);
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
	if (fill_stub(f->append, stub_vaddr, oeh->e_entry))
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

	if (oeh->e_phentsize != sizeof(Elf64_Phdr))
		return (fprintf(stderr, "unexpected e_phentsize\n"), -1);
	f->append = calloc(1, seg_size);
	if (!f->append)
		return (perror("calloc"), -1);
	f->append_len = seg_size;
	if (fill_stub(f->append, stub_vaddr, oeh->e_entry))
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

	if (eh->e_phnum == 0
		|| !in_bounds(f, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum))
		return (fprintf(stderr, "who makes these files?\n"), -1);
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
	if (write(fd, f->data, f->size) != (ssize_t)f->size)
		return (perror("write"), close(fd), -1);
	if (f->append_len
		&& write(fd, f->append, f->append_len) != (ssize_t)f->append_len)
		return (perror("write append"), close(fd), -1);
	for (int i = 0; i < f->npatch; i++)
		if (pwrite(fd, f->patch[i].buf, f->patch[i].len, f->patch[i].off)
			!= (ssize_t)f->patch[i].len)
			return (perror("pwrite patch"), close(fd), -1);
	close(fd);
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
	if (f.is64)
		rc = inject64(&f);
	else
		rc = (fprintf(stderr, "32-bit injection not implemented yet\n"), -1);
	if (rc == 0)
		rc = write_woody(&f);
	free(f.append);
	munmap(f.data, f.size);
	return (rc ? 1 : 0);
}
