#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include "woody.h" /* t_file, t_file_ops, DEFINE_STUB_PARAMS, ALIGN_*, in_bounds */

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define _swap16(_swap, v) ((uint16_t)!_swap ? v : ((v >> 8) | (v << 8)))

#define _swap32(_swap, v)                                                      \
	((uint32_t)!_swap ? v                                                      \
					  : ((v >> 24) | ((v >> 8) & 0xff00)                       \
						 | ((v << 8) & 0xff0000) | (v << 24)))

#define _swap64(_swap, v)                                                      \
	((uint64_t)!_swap ? v                                                      \
					  : (((uint64_t)_swap32((uint32_t)v) << 32)                \
						 | _swap32((uint32_t)(v >> 32))))

#ifndef DT_FLAGS_1
#define DT_FLAGS_1 0x6ffffffb
#endif
#ifndef DF_1_PIE
#define DF_1_PIE 0x08000000
#endif

#define STUB_VADDR_BASE 0x4000000UL
#define PAGE 0x1000UL

/* x86-64 ELF: 8-byte deltas/lengths (STUB_P_ENTRY_DELTA = 8, ...). */
DEFINE_STUB_PARAMS(STUB, 8);

/* x86 (i386) ELF: same magic, 4-byte deltas/lengths (STUB32_P_* = 8, 12, ...).
 */
DEFINE_STUB_PARAMS(STUB32, 4);

/* Marker stamped into the output's e_ident padding (EI_PAD = index 9, which the
 * kernel and ld.so ignore). Lets already_packed() recognise our own output in
 * O(1) instead of scanning the whole file for the stub magic. */
#define WOODY_MARK "WDY1"
#define WOODY_MARK_OFF 9
#define WOODY_MARK_LEN 4

int is_valid_elf(const uint8_t *data, const size_t size);

/* Pick the packing hooks for this file's class/ABI, or NULL if unsupported. */
const t_file_ops *elf_select_ops(const t_file *f);
int				  elf_prepare(t_file *f);

void print_phdr64(Elf64_Phdr *ph);
void print_phdr32(Elf32_Phdr *ph);

const char *conv_p_type(uint64_t type);
const char *conv_p_flags(Elf32_Word flags);

#endif
