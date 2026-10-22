#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* An in-place overwrite of a header region, max 64 bytes */
typedef struct s_patch
{
	size_t	off;
	size_t	len;
	uint8_t buf[64];
} t_patch;

typedef struct s_file
{
	uint8_t *data;
	size_t	 size;
	int		 is64;
	int		 swap;

	/* deltas computed by the injector, applied by write_woody */
	t_patch	 patch[2]; /* in-place overwrites (Ehdr, maybe one Phdr) */
	int		 npatch;
	uint8_t *append;
	size_t	 append_len;

	/* encrypted code region, a large malloc'd override pwritten at enc_off */
	uint8_t *enc;
	size_t	 enc_off;
	size_t	 enc_len;

	/* ChaCha20 secret, will be embedded into the stub so woody self-decrypts */
	uint8_t key[32];
	uint8_t nonce[12];
} t_file;

#define _swap16(_swap, v) ((uint16_t)!_swap ? v : ((v >> 8) | (v << 8)))

#define _swap32(_swap, v)                                                      \
	((uint32_t)!_swap ? v                                                      \
					  : ((v >> 24) | ((v >> 8) & 0xff00)                       \
						 | ((v << 8) & 0xff0000) | (v << 24)))

#define _swap64(_swap, v)                                                      \
	((uint64_t)!_swap ? v                                                      \
					  : (((uint64_t)_swap32((uint32_t)v) << 32)                \
						 | _swap32((uint32_t)(v >> 32))))

#define STUB_SIZE 0x1000UL
#define STUB_VADDR_BASE 0x4000000UL
#define PAGE 0x1000UL
/** 8-byte magic (see stub/stub.asm)
 * the packer locates it and fills the fields at these fixed byte offsets. */
#define STUB_PARAMS_MAGIC 0xDECAFFC0FFEEBABE
#define STUB_P_ENTRY_DELTA 8
#define STUB_P_REGION_DELTA 16
#define STUB_P_REGION_LEN 24
#define STUB_P_KEY 32
#define STUB_P_NONCE 64

int is_valid_elf(const uint8_t *data, const size_t size);

void print_phdr64(Elf64_Phdr *ph);
void print_phdr32(Elf32_Phdr *ph);

const char *conv_p_type(uint64_t type);
const char *conv_p_flags(Elf32_Word flags);

#endif