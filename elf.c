#include "elf_utils.h"
#include "stub.h"
#include "stub32.h"
#include <string.h>

int in_bounds(t_file *f, uint64_t offset, uint64_t len)
{
	return (offset < f->size && offset + len <= f->size);
}

void print_phdr64(Elf64_Phdr *ph)
{
	printf("{\n"
		   "  p_type   %s\n"
		   "  p_flags  %s\n"
		   "  p_offset %lu\n"
		   "  p_vaddr  %#0lX\n"
		   "  p_paddr  %#0lX\n"
		   "  p_filesz %lu\n"
		   "  p_memsz  %lu\n"
		   "  p_align  %lu\n"
		   "} Elf64_Phdr\n",
		   conv_p_type(ph->p_type),
		   conv_p_flags(ph->p_flags),
		   ph->p_offset,
		   ph->p_vaddr,
		   ph->p_paddr,
		   ph->p_filesz,
		   ph->p_memsz,
		   ph->p_align);
}

void print_phdr32(Elf32_Phdr *ph)
{
	printf("{\n"
		   "  p_type   = %s\n"
		   "  p_flags  = %s\n"
		   "  p_offset = %u\n"
		   "  p_vaddr  = %u\n"
		   "  p_paddr  = %0#x\n"
		   "  p_filesz = %0#x\n"
		   "  p_memsz  = %u\n"
		   "  p_align  = %u\n"
		   "} Elf32_Phdr\n",
		   conv_p_type(ph->p_type),
		   conv_p_flags(ph->p_flags),
		   ph->p_offset,
		   ph->p_vaddr,
		   ph->p_paddr,
		   ph->p_filesz,
		   ph->p_memsz,
		   ph->p_align);
}

struct s_data
{
	const char *name;
	uint64_t	val;
};

#define CASQT(name)                                                            \
	(struct s_data)                                                            \
	{                                                                          \
		#name, name                                                            \
	}

const char *conv_p_type(uint64_t type)
{
	static const struct s_data data[] = {
		CASQT(PT_NULL),		 CASQT(PT_LOAD),		 CASQT(PT_DYNAMIC),
		CASQT(PT_INTERP),	 CASQT(PT_NOTE),		 CASQT(PT_SHLIB),
		CASQT(PT_PHDR),		 CASQT(PT_TLS),			 CASQT(PT_NUM),
		CASQT(PT_LOOS),		 CASQT(PT_GNU_EH_FRAME), CASQT(PT_GNU_STACK),
		CASQT(PT_GNU_RELRO), CASQT(PT_GNU_PROPERTY), CASQT(PT_GNU_SFRAME),
		CASQT(PT_LOSUNW),	 CASQT(PT_SUNWBSS),		 CASQT(PT_SUNWSTACK),
		CASQT(PT_HISUNW),	 CASQT(PT_HIOS),		 CASQT(PT_LOPROC),
		CASQT(PT_HIPROC),
	};
	for (size_t i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
	{
		if (data[i].val == type)
			return (data[i].name);
	}
	return ("UNKOWN");
}

const char *conv_p_flags(Elf32_Word flags)
{
	static char				   ret[255] = {};
	static const struct s_data data[] = {
		CASQT(PF_X),
		CASQT(PF_W),
		CASQT(PF_R),
	};
	ret[0] = 0;
	if (!flags)
	{
		strcpy(ret, "0x0");
		return ret;
	}
	size_t len = 0;
	for (size_t i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
	{
		if (data[i].val & flags)
		{
			if (len)
				ret[len++] = '|';
			len += snprintf(ret + len, sizeof(ret) - len, "%s", data[i].name);
			flags &= ~data[i].val;
		}
	}
	if (flags & PF_MASKOS)
	{
		len += snprintf(ret + len,
						sizeof(ret) - len,
						"|%0#X",
						flags & PF_MASKOS);
		flags &= ~PF_MASKOS;
	}

	if (flags & PF_MASKPROC)
	{
		len += snprintf(ret + len,
						sizeof(ret) - len,
						"|%0#X",
						flags & PF_MASKPROC);
		flags &= ~PF_MASKPROC;
	}
	ret[len] = 0;
	return ret;
}

int is_valid_elf(const uint8_t *data, const size_t size)
{
	size_t ehsize;

	if (size < EI_NIDENT || memcmp(data, ELFMAG, SELFMAG) != 0
		|| data[EI_VERSION] != EV_CURRENT
		|| (data[EI_DATA] != ELFDATA2LSB && data[EI_DATA] != ELFDATA2MSB))
		return (0);
	if (data[EI_CLASS] == ELFCLASS64)
		ehsize = sizeof(Elf64_Ehdr);
	else if (data[EI_CLASS] == ELFCLASS32)
		ehsize = sizeof(Elf32_Ehdr);
	else
		return (0);
	return (size >= ehsize);
}

/* =========================== 64-bit packing =========================== */

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

/* Only things the kernel enters through e_entry can be packed: ET_EXEC, and
 * ET_DYN that are PIE executables. A shared library is also ET_DYN, but it is
 * entered through DT_INIT / DT_INIT_ARRAY when loaded, never e_entry, so our
 * stub would never run; the reliable "this is a program" signal is DF_1_PIE in
 * its DT_FLAGS_1. Relocatable (.o) and core files have no entry at all.
 */
static int is_pie_executable64(t_file *f)
{
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f->data;
	const Elf64_Phdr *ph;

	if (eh->e_type == ET_EXEC)
		return (1);
	if (eh->e_type != ET_DYN || eh->e_phentsize != sizeof(Elf64_Phdr)
		|| !in_bounds(f, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum))
		return (0);
	ph = (const Elf64_Phdr *)(f->data + eh->e_phoff);
	for (Elf64_Half i = 0; i < eh->e_phnum; i++)
	{
		const Elf64_Dyn *dyn;
		size_t			 n;

		if (ph[i].p_type != PT_DYNAMIC
			|| !in_bounds(f, ph[i].p_offset, ph[i].p_filesz))
			continue;
		dyn = (const Elf64_Dyn *)(f->data + ph[i].p_offset);
		n = ph[i].p_filesz / sizeof(Elf64_Dyn);
		for (size_t j = 0; j < n && dyn[j].d_tag != DT_NULL; j++)
			if (dyn[j].d_tag == DT_FLAGS_1)
				return ((dyn[j].d_un.d_val & DF_1_PIE) != 0);
		return (0); /* dynamic section but no DF_1_PIE: a shared library */
	}
	return (0); /* ET_DYN with no usable PT_DYNAMIC */
}

/* Patch the stub's parameter block (found by its magic) inside `slot`. */
static int fill_stub(uint8_t *slot,
					 uint64_t stub_vaddr,
					 uint64_t src_delta,
					 t_file	 *f)
{
	const uint64_t magic = STUB_PARAMS_MAGIC;
	const int64_t  delta = (int64_t)f->entry - (int64_t)stub_vaddr;
	size_t		   i;
	uint8_t		  *p;

	memcpy(slot, stub_bin, stub_bin_len);
	for (i = 0; i + sizeof(magic) <= stub_bin_len; i++)
		if (memcmp(slot + i, &magic, sizeof(magic)) == 0)
			break;
	if (i + sizeof(magic) > stub_bin_len)
		return (fprintf(stderr, "stub params magic not found\n"), -1);
	p = slot + i;
	memcpy(p + STUB_P_ENTRY_DELTA, &delta, sizeof(delta));
	memcpy(p + STUB_P_REGION_DELTA, &delta, sizeof(delta));
	memcpy(p + STUB_P_REGION_LEN, &f->region_len, sizeof(f->region_len));
	memcpy(p + STUB_P_SRC_DELTA, &src_delta, sizeof(src_delta));
	memcpy(p + STUB_P_COMP_LEN, &f->comp_len, sizeof(f->comp_len));
	memcpy(p + STUB_P_KEY, f->key, sizeof(f->key));
	memcpy(p + STUB_P_NONCE, f->nonce, sizeof(f->nonce));
	p[STUB_P_ANTIDBG] = f->anti_debug ? 1 : 0;
	return (0);
}

/* Rewrite one carried-over program header for the compacted layout: slide its
 * file offset down past the cut, and turn the code region into bss. */
static void patch_phdr64(Elf64_Phdr *p, uint64_t cut_end, uint64_t K, t_file *f)
{
	if (p->p_offset >= cut_end)
		p->p_offset -= K;
	if (p->p_type == PT_LOAD && (p->p_flags & PF_X) && f->entry >= p->p_vaddr
		&& f->entry < p->p_vaddr + p->p_memsz)
		p->p_filesz = f->region_off - p->p_offset; /* region -> bss */
}

static void set_stub_phdr64(Elf64_Phdr *p,
							uint64_t	vaddr,
							size_t		off,
							size_t		sz)
{
	p->p_type = PT_LOAD;
	p->p_flags = PF_R | PF_X; /* X is for the stub; the blob just shares it */
	p->p_offset = off;
	p->p_vaddr = vaddr;
	p->p_paddr = vaddr;
	p->p_filesz = sz;
	p->p_memsz = sz;
	p->p_align = PAGE;
}

/* Everything build_output64 works out about the output's shape, so computing
 * the geometry (plan_layout64) stays separate from writing it (emit_output64).
 */
typedef struct s_layout
{
	int		   note;	 /* PT_NOTE slot to hijack, or -1 */
	Elf64_Half phnum;	 /* original program-header count */
	Elf64_Half newphnum; /* output count (phnum, or phnum+1 with no note) */
	uint64_t   seg_end;	 /* region end in the original file */
	uint64_t cut_start;	 /* removed window [cut_start, cut_end), page-aligned */
	uint64_t cut_end;
	uint64_t K;			/* bytes removed; 0 if compaction was skipped */
	size_t	 kept_end;	/* end of the loadable file content we keep */
	size_t	 stub_off;	/* file offset of the appended stub segment */
	size_t	 phtab_off; /* file offset of the program-header table */
	size_t	 blob_off;	/* file offset of the compressed+encrypted blob */
	size_t	 tab_bytes; /* program-header table size */
	uint64_t stub_vaddr;
	uint64_t phtab_vaddr;
} t_layout;

/* Work out the compacted output's geometry: the page-aligned window to remove,
 * where the kept content ends, and where the stub, phdr table and blob land.
 * Also sets f->out_len. */
static int plan_layout64(t_file *f, t_layout *lo)
{
	const Elf64_Ehdr *oeh = (const Elf64_Ehdr *)f->data;
	const Elf64_Phdr *oph = (const Elf64_Phdr *)(f->data + oeh->e_phoff);
	size_t			  pre_stub;

	lo->note = find_phnote_index64(f);
	lo->phnum = oeh->e_phnum;
	lo->newphnum = (lo->note >= 0) ? lo->phnum : (Elf64_Half)(lo->phnum + 1);
	lo->seg_end = f->region_off + f->region_len;
	lo->cut_start = ALIGN_UP(f->region_off, PAGE);
	lo->cut_end = ALIGN_DOWN(lo->seg_end, PAGE);
	if (oeh->e_phoff >= lo->cut_start && lo->cut_start)
		return (fprintf(stderr, "phdr table inside cut window\n"), -1);
	/* a whole number of pages must be removed, or the segments after the cut
	 * lose their p_vaddr == p_offset (mod align) congruence. */
	lo->K = (lo->cut_end > lo->cut_start) ? (lo->cut_end - lo->cut_start) : 0;
	for (Elf64_Half i = 0; lo->K && i < lo->phnum; i++)
	{
		if (i == (Elf64_Half)lo->note)
			continue;
		if (oph[i].p_offset >= lo->cut_start && oph[i].p_offset < lo->cut_end)
		{
			lo->K = 0; /* a segment starts inside the window: skip compaction */
			break;
		}
	}
	if (!lo->K)
		lo->cut_start = lo->cut_end = 0;
	lo->kept_end = 0;
	for (Elf64_Half i = 0; i < lo->phnum; i++)
	{
		if (oph[i].p_type == PT_LOAD
			&& oph[i].p_offset + oph[i].p_filesz > lo->kept_end)
			lo->kept_end = oph[i].p_offset + oph[i].p_filesz;
	}

	pre_stub = (size_t)(lo->cut_start + (lo->kept_end - lo->cut_end));
	/* No page alignment needed: stub_vaddr = STUB_VADDR_BASE (page-aligned) +
	 * stub_off keeps p_vaddr == p_offset (mod PAGE) for any stub_off, so the
	 * stub can sit right after the kept content instead of a page later. */
	lo->stub_off = (size_t)ALIGN_UP(pre_stub, 8);
	lo->tab_bytes = (size_t)lo->newphnum * sizeof(Elf64_Phdr);
	/* The blob gets its own pages so the stub can mprotect it writable for
	 * in-place decryption without touching its own R+X code pages. With a
	 * PT_NOTE the phdr table stays put; otherwise the enlarged table rides
	 * between the stub and the blob, and e_phoff is repointed to it. */
	if (lo->note >= 0)
	{
		lo->phtab_off = oeh->e_phoff;
		lo->blob_off = (size_t)ALIGN_UP(lo->stub_off + stub_bin_len, PAGE);
	}
	else
	{
		lo->phtab_off = (size_t)ALIGN_UP(lo->stub_off + stub_bin_len, 8);
		lo->blob_off = (size_t)ALIGN_UP(lo->phtab_off + lo->tab_bytes, PAGE);
	}
	f->out_len = lo->blob_off + f->comp_len;
	/* Place the stub segment above every original PT_LOAD so its R+X pages can
	 * never be overlaid by an original (possibly RW) segment -- a fixed base is
	 * not enough, since a large binary's vaddrs can climb past it. Keeping the
	 * base page-aligned preserves p_vaddr == p_offset (mod PAGE) for any
	 * stub_off, so only the in-page part of stub_off is carried over. */
	uint64_t max_vend = STUB_VADDR_BASE;
	for (Elf64_Half i = 0; i < lo->phnum; i++)
		if (oph[i].p_type == PT_LOAD
			&& oph[i].p_vaddr + oph[i].p_memsz > max_vend)
			max_vend = oph[i].p_vaddr + oph[i].p_memsz;
	lo->stub_vaddr = ALIGN_UP(max_vend, PAGE) + (lo->stub_off & (PAGE - 1));
	lo->phtab_vaddr = lo->stub_vaddr + (lo->phtab_off - lo->stub_off);
	return (0);
}

/* copy the kept bytes (minus the cut), scrub the leftover plaintext,
 * patch the program headers, embed the stub and blob */
static int emit_output64(t_file *f, const t_layout *lo)
{
	uint8_t	   *out;
	Elf64_Ehdr *eh;
	Elf64_Phdr *ph;

	out = calloc(1, f->out_len);
	if (!out)
		return (perror("calloc"), -1);
	memcpy(out, f->data, lo->cut_start);
	memcpy(out + lo->cut_start,
		   f->data + lo->cut_end,
		   lo->kept_end - lo->cut_end);
	/* scrub the plaintext */
	if (!lo->K)
		memset(out + f->region_off, 0, (size_t)(lo->seg_end - f->region_off));
	else
	{
		if (lo->cut_start > f->region_off)
			memset(out + f->region_off,
				   0,
				   (size_t)(lo->cut_start - f->region_off));
		if (lo->seg_end > lo->cut_end)
			memset(out + lo->cut_start, 0, (size_t)(lo->seg_end - lo->cut_end));
	}

	eh = (Elf64_Ehdr *)out;
	if (lo->note >= 0)
	{
		/* repurpose the PT_NOTE slot in the existing, in-place table */
		ph = (Elf64_Phdr *)(out + eh->e_phoff);
		for (Elf64_Half i = 0; i < lo->phnum; i++)
			patch_phdr64(&ph[i], lo->cut_end, lo->K, f);
		set_stub_phdr64(&ph[lo->note],
						lo->stub_vaddr,
						lo->stub_off,
						f->out_len - lo->stub_off);
	}
	else
	{
		/* relocate an enlarged copy of the table into the appended segment */
		ph = (Elf64_Phdr *)(out + lo->phtab_off);
		memcpy(ph, out + eh->e_phoff, (size_t)lo->phnum * sizeof(Elf64_Phdr));
		for (Elf64_Half i = 0; i < lo->phnum; i++)
		{
			patch_phdr64(&ph[i], lo->cut_end, lo->K, f);
			if (ph[i].p_type == PT_PHDR)
			{
				ph[i].p_offset = lo->phtab_off;
				ph[i].p_vaddr = lo->phtab_vaddr;
				ph[i].p_paddr = lo->phtab_vaddr;
				ph[i].p_filesz = lo->tab_bytes;
				ph[i].p_memsz = lo->tab_bytes;
			}
		}
		set_stub_phdr64(&ph[lo->phnum],
						lo->stub_vaddr,
						lo->stub_off,
						f->out_len - lo->stub_off);
		eh->e_phoff = lo->phtab_off;
		eh->e_phnum = lo->newphnum;
	}
	eh->e_entry = lo->stub_vaddr;
	eh->e_shoff = 0;
	eh->e_shnum = 0;
	eh->e_shstrndx = 0;
	memcpy(out + WOODY_MARK_OFF,
		   WOODY_MARK,
		   WOODY_MARK_LEN); /* re-pack guard */

	if (fill_stub(out + lo->stub_off,
				  lo->stub_vaddr,
				  lo->blob_off - lo->stub_off,
				  f))
		return (free(out), -1);
	memcpy(out + lo->blob_off, f->blob, f->comp_len);
	f->out = out;
	fprintf(stderr,
			"[woody] %s  cut=%#zx stub@%#zx  %#zx -> %#zx bytes\n",
			lo->note >= 0 ? "PT_NOTE hijack"
						  : "new PT_LOAD (phdr table relocated)",
			(size_t)lo->K,
			lo->stub_off,
			f->size,
			f->out_len);
	return (0);
}

/*
 * Reject anything not entered through e_entry: shared objects (incl. the
 * runnable libc.so), relocatable .o files (where e_phnum is legitimately 0)
 * and core dumps. Classify before the phdr check so each gets the right
 * message.
 */
static int validate64(t_file *f)
{
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f->data;

	if (!is_pie_executable64(f))
		return (
			fprintf(stderr,
					"not a packable executable (e_type=%u): shared objects, "
					"relocatable and core files are unsupported\n",
					eh->e_type),
			-1);
	if (eh->e_phnum == 0 || eh->e_phentsize != sizeof(Elf64_Phdr)
		|| !in_bounds(f, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum))
		return (fprintf(stderr, "malformed program header table\n"), -1);
	return (0);
}

/* Locate the code region to pack: from the original entry to the end of its
 * executable segment's file content. */
static int find_region64(t_file *f)
{
	const Elf64_Ehdr *oeh = (const Elf64_Ehdr *)f->data;
	const uint64_t	  entry = oeh->e_entry;
	const Elf64_Phdr *seg = find_exec_load64(f, entry);
	uint64_t		  seg_end;

	if (!seg)
		return (fprintf(stderr, "no executable segment for entry\n"), -1);
	f->region_off = entry - seg->p_vaddr + seg->p_offset;
	seg_end = seg->p_offset + seg->p_filesz;
	if (f->region_off >= seg_end
		|| !in_bounds(f, f->region_off, seg_end - f->region_off))
		return (fprintf(stderr, "bad code region\n"), -1);
	f->region_len = seg_end - f->region_off;
	f->entry = entry;
	return (0);
}

/*
 * Assemble the output: remove the page-aligned window inside the code region,
 * shift every file offset past the cut down by K, make the region bss-style
 * (filesz stops at entry, memsz unchanged), strip the section headers, and
 * append [stub][blob] as a new R+X PT_LOAD with e_entry retargeted to the stub.
 * The blob sits on its own pages so the stub can mprotect it writable for
 * in-place decryption; no segment is ever both writable and executable.
 *
 * The new PT_LOAD needs a program-header slot: with a spare PT_NOTE we
 * repurpose it in place, otherwise we grow the table by one entry and relocate
 * it (so binaries without a PT_NOTE are still supported).
 */
static int build_output64(t_file *f)
{
	t_layout lo;

	if (plan_layout64(f, &lo))
		return (-1);
	return (emit_output64(f, &lo));
}

/* =========================== 32-bit packing =========================== */
/* Mostly the same, just the stub and some widths differ */

static int find_phnote_index32(t_file *f)
{
	const Elf32_Ehdr *eh = (Elf32_Ehdr *)f->data;
	const Elf32_Phdr *ph = (Elf32_Phdr *)(f->data + eh->e_phoff);

	for (Elf32_Half i = 0; i < eh->e_phnum; i++)
		if (ph[i].p_type == PT_NOTE)
			return (i);
	return (-1);
}

static const Elf32_Phdr *find_exec_load32(t_file *f, uint32_t entry)
{
	const Elf32_Ehdr *eh = (const Elf32_Ehdr *)f->data;
	const Elf32_Phdr *ph = (const Elf32_Phdr *)(f->data + eh->e_phoff);

	for (Elf32_Half i = 0; i < eh->e_phnum; i++)
		if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)
			&& entry >= ph[i].p_vaddr && entry < ph[i].p_vaddr + ph[i].p_filesz)
			return (&ph[i]);
	return (NULL);
}

static int is_pie_executable32(t_file *f)
{
	const Elf32_Ehdr *eh = (const Elf32_Ehdr *)f->data;
	const Elf32_Phdr *ph;

	if (eh->e_type == ET_EXEC)
		return (1);
	if (eh->e_type != ET_DYN || eh->e_phentsize != sizeof(Elf32_Phdr)
		|| !in_bounds(f, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum))
		return (0);
	ph = (const Elf32_Phdr *)(f->data + eh->e_phoff);
	for (Elf32_Half i = 0; i < eh->e_phnum; i++)
	{
		const Elf32_Dyn *dyn;
		size_t			 n;

		if (ph[i].p_type != PT_DYNAMIC
			|| !in_bounds(f, ph[i].p_offset, ph[i].p_filesz))
			continue;
		dyn = (const Elf32_Dyn *)(f->data + ph[i].p_offset);
		n = ph[i].p_filesz / sizeof(Elf32_Dyn);
		for (size_t j = 0; j < n && dyn[j].d_tag != DT_NULL; j++)
			if (dyn[j].d_tag == DT_FLAGS_1)
				return ((dyn[j].d_un.d_val & DF_1_PIE) != 0);
		return (0);
	}
	return (0);
}

static int fill_stub32(uint8_t *slot,
					   uint32_t stub_vaddr,
					   uint32_t src_delta,
					   t_file  *f)
{
	const uint64_t magic = STUB_PARAMS_MAGIC;
	const int32_t  delta = (int32_t)((uint32_t)f->entry - stub_vaddr);
	const uint32_t rlen = (uint32_t)f->region_len;
	const uint32_t clen = (uint32_t)f->comp_len;
	size_t		   i;
	uint8_t		  *p;

	memcpy(slot, stub32_bin, stub32_bin_len);
	for (i = 0; i + sizeof(magic) <= stub32_bin_len; i++)
		if (memcmp(slot + i, &magic, sizeof(magic)) == 0)
			break;
	if (i + sizeof(magic) > stub32_bin_len)
		return (fprintf(stderr, "stub32 params magic not found\n"), -1);
	p = slot + i;
	memcpy(p + STUB32_P_ENTRY_DELTA, &delta, sizeof(delta));
	memcpy(p + STUB32_P_REGION_DELTA, &delta, sizeof(delta));
	memcpy(p + STUB32_P_REGION_LEN, &rlen, sizeof(rlen));
	memcpy(p + STUB32_P_SRC_DELTA, &src_delta, sizeof(src_delta));
	memcpy(p + STUB32_P_COMP_LEN, &clen, sizeof(clen));
	memcpy(p + STUB32_P_KEY, f->key, sizeof(f->key));
	memcpy(p + STUB32_P_NONCE, f->nonce, sizeof(f->nonce));
	p[STUB32_P_ANTIDBG] = f->anti_debug ? 1 : 0;
	return (0);
}

static void patch_phdr32(Elf32_Phdr *p, uint64_t cut_end, uint64_t K, t_file *f)
{
	if (p->p_offset >= cut_end)
		p->p_offset -= (uint32_t)K;
	if (p->p_type == PT_LOAD && (p->p_flags & PF_X) && f->entry >= p->p_vaddr
		&& f->entry < p->p_vaddr + p->p_memsz)
		p->p_filesz = (uint32_t)f->region_off - p->p_offset; /* region -> bss */
}

static void set_stub_phdr32(Elf32_Phdr *p,
							uint32_t	vaddr,
							size_t		off,
							size_t		sz)
{
	p->p_type = PT_LOAD;
	p->p_flags = PF_R | PF_X; /* X is for the stub; the blob just shares it */
	p->p_offset = (uint32_t)off;
	p->p_vaddr = vaddr;
	p->p_paddr = vaddr;
	p->p_filesz = (uint32_t)sz;
	p->p_memsz = (uint32_t)sz;
	p->p_align = PAGE;
}

static int plan_layout32(t_file *f, t_layout *lo)
{
	const Elf32_Ehdr *oeh = (const Elf32_Ehdr *)f->data;
	const Elf32_Phdr *oph = (const Elf32_Phdr *)(f->data + oeh->e_phoff);
	size_t			  pre_stub;

	lo->note = find_phnote_index32(f);
	lo->phnum = oeh->e_phnum;
	lo->newphnum = (lo->note >= 0) ? lo->phnum : (Elf32_Half)(lo->phnum + 1);
	lo->seg_end = f->region_off + f->region_len;
	lo->cut_start = ALIGN_UP(f->region_off, PAGE);
	lo->cut_end = ALIGN_DOWN(lo->seg_end, PAGE);
	if (oeh->e_phoff >= lo->cut_start && lo->cut_start)
		return (fprintf(stderr, "phdr table inside cut window\n"), -1);
	lo->K = (lo->cut_end > lo->cut_start) ? (lo->cut_end - lo->cut_start) : 0;
	for (Elf32_Half i = 0; lo->K && i < lo->phnum; i++)
	{
		if (i == (Elf32_Half)lo->note)
			continue;
		if (oph[i].p_offset >= lo->cut_start && oph[i].p_offset < lo->cut_end)
		{
			lo->K = 0;
			break;
		}
	}
	if (!lo->K)
		lo->cut_start = lo->cut_end = 0;
	lo->kept_end = 0;
	for (Elf32_Half i = 0; i < lo->phnum; i++)
	{
		if (oph[i].p_type == PT_LOAD
			&& oph[i].p_offset + oph[i].p_filesz > lo->kept_end)
			lo->kept_end = oph[i].p_offset + oph[i].p_filesz;
	}

	pre_stub = (size_t)(lo->cut_start + (lo->kept_end - lo->cut_end));
	lo->stub_off = (size_t)ALIGN_UP(pre_stub, 8);
	lo->tab_bytes = (size_t)lo->newphnum * sizeof(Elf32_Phdr);
	if (lo->note >= 0)
	{
		lo->phtab_off = oeh->e_phoff;
		lo->blob_off = (size_t)ALIGN_UP(lo->stub_off + stub32_bin_len, PAGE);
	}
	else
	{
		lo->phtab_off = (size_t)ALIGN_UP(lo->stub_off + stub32_bin_len, 8);
		lo->blob_off = (size_t)ALIGN_UP(lo->phtab_off + lo->tab_bytes, PAGE);
	}
	f->out_len = lo->blob_off + f->comp_len;
	/* Same rule as 64-bit: sit the stub above every original PT_LOAD, keeping a
	 * page-aligned base so p_vaddr == p_offset (mod PAGE) still holds. */
	uint32_t max_vend = STUB_VADDR_BASE;
	for (Elf32_Half i = 0; i < lo->phnum; i++)
		if (oph[i].p_type == PT_LOAD
			&& oph[i].p_vaddr + oph[i].p_memsz > max_vend)
			max_vend = oph[i].p_vaddr + oph[i].p_memsz;
	lo->stub_vaddr = ALIGN_UP(max_vend, PAGE) + (lo->stub_off & (PAGE - 1));
	lo->phtab_vaddr = lo->stub_vaddr + (lo->phtab_off - lo->stub_off);
	return (0);
}

static int emit_output32(t_file *f, const t_layout *lo)
{
	uint8_t	   *out;
	Elf32_Ehdr *eh;
	Elf32_Phdr *ph;

	out = calloc(1, f->out_len);
	if (!out)
		return (perror("calloc"), -1);
	memcpy(out, f->data, lo->cut_start);
	memcpy(out + lo->cut_start,
		   f->data + lo->cut_end,
		   lo->kept_end - lo->cut_end);
	if (!lo->K)
		memset(out + f->region_off, 0, (size_t)(lo->seg_end - f->region_off));
	else
	{
		if (lo->cut_start > f->region_off)
			memset(out + f->region_off,
				   0,
				   (size_t)(lo->cut_start - f->region_off));
		if (lo->seg_end > lo->cut_end)
			memset(out + lo->cut_start, 0, (size_t)(lo->seg_end - lo->cut_end));
	}

	eh = (Elf32_Ehdr *)out;
	if (lo->note >= 0)
	{
		ph = (Elf32_Phdr *)(out + eh->e_phoff);
		for (Elf32_Half i = 0; i < lo->phnum; i++)
			patch_phdr32(&ph[i], lo->cut_end, lo->K, f);
		set_stub_phdr32(&ph[lo->note],
						(uint32_t)lo->stub_vaddr,
						lo->stub_off,
						f->out_len - lo->stub_off);
	}
	else
	{
		ph = (Elf32_Phdr *)(out + lo->phtab_off);
		memcpy(ph, out + eh->e_phoff, (size_t)lo->phnum * sizeof(Elf32_Phdr));
		for (Elf32_Half i = 0; i < lo->phnum; i++)
		{
			patch_phdr32(&ph[i], lo->cut_end, lo->K, f);
			if (ph[i].p_type == PT_PHDR)
			{
				ph[i].p_offset = (uint32_t)lo->phtab_off;
				ph[i].p_vaddr = (uint32_t)lo->phtab_vaddr;
				ph[i].p_paddr = (uint32_t)lo->phtab_vaddr;
				ph[i].p_filesz = (uint32_t)lo->tab_bytes;
				ph[i].p_memsz = (uint32_t)lo->tab_bytes;
			}
		}
		set_stub_phdr32(&ph[lo->phnum],
						(uint32_t)lo->stub_vaddr,
						lo->stub_off,
						f->out_len - lo->stub_off);
		eh->e_phoff = (uint32_t)lo->phtab_off;
		eh->e_phnum = lo->newphnum;
	}
	eh->e_entry = (uint32_t)lo->stub_vaddr;
	eh->e_shoff = 0;
	eh->e_shnum = 0;
	eh->e_shstrndx = 0;
	memcpy(out + WOODY_MARK_OFF,
		   WOODY_MARK,
		   WOODY_MARK_LEN); /* re-pack guard */

	if (fill_stub32(out + lo->stub_off,
					(uint32_t)lo->stub_vaddr,
					(uint32_t)(lo->blob_off - lo->stub_off),
					f))
		return (free(out), -1);
	memcpy(out + lo->blob_off, f->blob, f->comp_len);
	f->out = out;
	fprintf(stderr,
			"[woody] %s  cut=%#zx stub@%#zx  %#zx -> %#zx bytes\n",
			lo->note >= 0 ? "PT_NOTE hijack"
						  : "new PT_LOAD (phdr table relocated)",
			(size_t)lo->K,
			lo->stub_off,
			f->size,
			f->out_len);
	return (0);
}

static int validate32(t_file *f)
{
	const Elf32_Ehdr *eh = (const Elf32_Ehdr *)f->data;

	if (!is_pie_executable32(f))
		return (
			fprintf(stderr,
					"not a packable executable (e_type=%u): shared objects, "
					"relocatable and core files are unsupported\n",
					eh->e_type),
			-1);
	if (eh->e_phnum == 0 || eh->e_phentsize != sizeof(Elf32_Phdr)
		|| !in_bounds(f, eh->e_phoff, (uint64_t)eh->e_phentsize * eh->e_phnum))
		return (fprintf(stderr, "malformed program header table\n"), -1);
	return (0);
}

static int find_region32(t_file *f)
{
	const Elf32_Ehdr *oeh = (const Elf32_Ehdr *)f->data;
	const uint32_t	  entry = oeh->e_entry;
	const Elf32_Phdr *seg = find_exec_load32(f, entry);
	uint32_t		  seg_end;

	if (!seg)
		return (fprintf(stderr, "no executable segment for entry\n"), -1);
	f->region_off = entry - seg->p_vaddr + seg->p_offset;
	seg_end = seg->p_offset + seg->p_filesz;
	if (f->region_off >= seg_end
		|| !in_bounds(f, f->region_off, seg_end - f->region_off))
		return (fprintf(stderr, "bad code region\n"), -1);
	f->region_len = seg_end - f->region_off;
	f->entry = entry;
	return (0);
}

static int build_output32(t_file *f)
{
	t_layout lo;

	if (plan_layout32(f, &lo))
		return (-1);
	return (emit_output32(f, &lo));
}

/* Our output carries a marker in its e_ident padding (EI_PAD = index 9, which
 * the kernel and ld.so ignore); if we see it, the file is already packed and we
 * refuse rather than onion-packing. O(1) check. */
static int is_packed_elf(const t_file *f)
{
	return (f->size >= EI_NIDENT
			&& memcmp(f->data + WOODY_MARK_OFF, WOODY_MARK, WOODY_MARK_LEN)
				   == 0);
}

static const t_file_ops g_elf64 = {
	.name = "elf64",
	.validate = validate64,
	.find_region = find_region64,
	.build_output = build_output64,
	.is_packed = is_packed_elf,
};

static const t_file_ops g_elf32 = {
	.name = "elf32",
	.validate = validate32,
	.find_region = find_region32,
	.build_output = build_output32,
	.is_packed = is_packed_elf,
};

const t_file_ops *elf_select_ops(const t_file *f)
{
	if (f->swap)
		return (NULL); /* opposite-endian ELF: unsupported */
	return (f->is64 ? &g_elf64 : &g_elf32);
}

/* Validate an already-mapped ELF and fill in the class/endianness fields the
 * packing hooks rely on. Assumes f->data / f->size are set. */
int elf_prepare(t_file *f)
{
	const uint16_t one = 1;

	if (is_valid_elf(f->data, f->size) == 0)
		return (fprintf(stderr, "file is not valid elf\n"), -1);
	f->is64 = f->data[EI_CLASS] == ELFCLASS64;
	f->swap = (f->data[EI_DATA] == ELFDATA2LSB)
			  != (*(const uint8_t *)&one == 1);
	return (0);
}