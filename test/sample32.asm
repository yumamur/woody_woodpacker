; 32-bit test fixture: prints a line and exits 42. Built with
; `nasm -f elf32` + `ld -m elf_i386` so the suite can exercise the 32-bit
; packer without a -m32 C toolchain.
BITS 32
global _start
section .text
_start:
	mov     eax, 4          ; SYS_write
	mov     ebx, 1
	mov     ecx, msg
	mov     edx, mlen
	int     0x80
	mov     eax, 1          ; SYS_exit
	mov     ebx, 42
	int     0x80
section .rodata
msg:
	db      "sample32 output", 10
mlen equ $ - msg
