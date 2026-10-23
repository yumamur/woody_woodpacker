#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct s_file
{
	uint8_t *data;
	size_t	 size;
	int		 is64;
	int		 swap;

	/* compressed+encrypted payload (the original code region) */
	uint8_t *blob;
	size_t	 comp_len;	 /* Lc: compressed + encrypted length */
	size_t	 region_off; /* file offset of the region (== original entry) */
	size_t	 region_len; /* L: original / decompressed length */
	uint64_t entry;		 /* original e_entry */

	/* fully assembled (compacted) output image, written out verbatim */
	uint8_t *out;
	size_t	 out_len;

	/* ChaCha20 secret, embedded into the stub so woody self-decrypts */
	uint8_t key[32];
	uint8_t nonce[12];
} t_file;

/*
 * Per-flavour packing hooks. Each supported ELF class/ABI provides one table
 * (elf.c has the 64-bit one; 32-bit plugs in the same way). The class-agnostic
 * steps -- key generation, compression+encryption, writing -- live in main.c
 * and call these for the parts that depend on ELF structure width.
 */
typedef struct s_elf_ops
{
	const char *name;
	int (*validate)(t_file *f);		/* reject non-packable inputs */
	int (*find_region)(t_file *f);	/* set region_off / region_len / entry */
	int (*build_output)(t_file *f); /* produce out / out_len */
} t_elf_ops;

#define _swap16(_swap, v) ((uint16_t)!_swap ? v : ((v >> 8) | (v << 8)))

#define _swap32(_swap, v)                                                      \
	((uint32_t)!_swap ? v                                                      \
					  : ((v >> 24) | ((v >> 8) & 0xff00)                       \
						 | ((v << 8) & 0xff0000) | (v << 24)))

#define _swap64(_swap, v)                                                      \
	((uint64_t)!_swap ? v                                                      \
					  : (((uint64_t)_swap32((uint32_t)v) << 32)                \
						 | _swap32((uint32_t)(v >> 32))))

#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((uint64_t)(a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((uint64_t)(a) - 1))

#ifndef DT_FLAGS_1
#define DT_FLAGS_1 0x6ffffffb
#endif
#ifndef DF_1_PIE
#define DF_1_PIE 0x08000000
#endif

#define STUB_VADDR_BASE 0x4000000UL
#define PAGE 0x1000UL
/** 8-byte magic (see stub/stub.asm)
 * the packer locates it and fills the fields at these fixed byte offsets. */
#define STUB_PARAMS_MAGIC 0xDECAFFC0FFEEBABE
#define STUB_P_ENTRY_DELTA 8
#define STUB_P_REGION_DELTA 16
#define STUB_P_REGION_LEN 24
#define STUB_P_SRC_DELTA 32
#define STUB_P_COMP_LEN 40
#define STUB_P_KEY 48
#define STUB_P_NONCE 80

/* Marker stamped into the output's e_ident padding (EI_PAD = index 9, which the
 * kernel and ld.so ignore). Lets already_packed() recognise our own output in
 * O(1) instead of scanning the whole file for the stub magic. */
#define WOODY_MARK "WDY1"
#define WOODY_MARK_OFF 9
#define WOODY_MARK_LEN 4

int is_valid_elf(const uint8_t *data, const size_t size);
int in_bounds(t_file *f, uint64_t offset, uint64_t len);

/* Pick the packing hooks for this file's class/ABI, or NULL if unsupported. */
const t_elf_ops *elf_select_ops(const t_file *f);

void print_phdr64(Elf64_Phdr *ph);
void print_phdr32(Elf32_Phdr *ph);

const char *conv_p_type(uint64_t type);
const char *conv_p_flags(Elf32_Word flags);

#endif
