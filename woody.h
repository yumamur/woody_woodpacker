#ifndef WOODY_H
#define WOODY_H

/*
 * Format-agnostic packer core, shared by every container backend (ELF in
 * elf_utils.h, PE in pe_utils.h, future formats the same way). It holds the
 * pieces that do not depend on a specific executable format: the in-memory
 * file/ops contract the pack pipeline in main.c drives, the stub
 * parameter-block layout generator, and a couple of generic helpers.
 * Container-specific structures and declarations stay in that container's own
 * header; only what both sides genuinely share belongs here.
 */

#include <stddef.h>
#include <stdint.h>

/*
 * One input being packed, shared by all backends. The format-specific hooks
 * fill region_off/region_len/entry and build `out`; the class-agnostic steps
 * (key generation, compression, encryption, writing) live in main.c.
 */
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

	/* optional (-a): stamp the ELF stub (32/64) to hide the WOODY banner when
	 * traced. Format-agnostic storage; only the ELF backend consumes it. */
	int anti_debug;
} t_file;

/*
 * Per-flavour packing hooks. Each supported container/class provides one table
 * (elf.c for ELF, pe.c for PE). The class-agnostic steps -- key generation,
 * compression+encryption, writing -- live in main.c and call these for the
 * parts that depend on the container's structure.
 */
typedef struct s_file_ops
{
	const char *name;
	int (*validate)(t_file *f);		   /* reject non-packable inputs */
	int (*find_region)(t_file *f);	   /* set region_off / region_len / entry */
	int (*build_output)(t_file *f);	   /* produce out / out_len */
	int (*is_packed)(const t_file *f); /* recognise our already-packed output */
} t_file_ops;

#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((uint64_t)(a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((uint64_t)(a) - 1))

/* 8-byte magic (see the stub .asm sources): the packer locates the stub's
 * parameter block by this value and fills the fields at DEFINE_STUB_PARAMS. */
#define STUB_PARAMS_MAGIC 0xDECAFFC0FFEEBABE

/*
 * Stub param-block layout generator. Every flavour lays the block out the same
 * way -- an 8-byte magic, five delta/length fields, then the 32-byte ChaCha20
 * key and 12-byte nonce -- and differs only in how wide those middle fields
 * are: 8 bytes for a 64-bit target, 4 for a 32-bit one. Expanding this once per
 * flavour yields the full set of PFX##_P_* byte offsets, so the layout lives in
 * exactly one place and the 64/32-bit blocks can never silently drift apart.
 *
 * The per-flavour expansions live in each container's header: STUB / STUB32 in
 * elf_utils.h, STUBPE / STUBPE32 in pe_utils.h. A new backend plugs in the same
 * way -- pick a prefix and the target's pointer width, e.g.
 *   DEFINE_STUB_PARAMS(STUBAARCH64, 8);
 *   DEFINE_STUB_PARAMS(STUBARM32,   4);
 *
 *   PFX -- symbol prefix (STUB, STUB32, STUBPE, ...)
 *   W   -- width in bytes of each delta/length field (native pointer width)
 */
#define DEFINE_STUB_PARAMS(PFX, W)                                             \
	enum                                                                       \
	{                                                                          \
		PFX##_P_ENTRY_DELTA = 8,                                               \
		PFX##_P_REGION_DELTA = PFX##_P_ENTRY_DELTA + (W),                      \
		PFX##_P_REGION_LEN = PFX##_P_REGION_DELTA + (W),                       \
		PFX##_P_SRC_DELTA = PFX##_P_REGION_LEN + (W),                          \
		PFX##_P_COMP_LEN = PFX##_P_SRC_DELTA + (W),                            \
		PFX##_P_KEY = PFX##_P_COMP_LEN + (W),                                  \
		PFX##_P_NONCE = PFX##_P_KEY + 32,                                      \
		PFX##_P_ANTIDBG = PFX##_P_NONCE                                        \
						  + 12 /* 1-byte flag (consumed by the ELF stub only) */\
	}

/* Bounds-check [offset, offset+len) against f->size. Shared by all backends. */
int in_bounds(t_file *f, uint64_t offset, uint64_t len);

#endif
