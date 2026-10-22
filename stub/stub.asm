; 1- write(1, "....WOODY....\n", 14)
; 2- mprotect the encrypted code region writable
; 3- ChaCha20-decrypt it in place (key/nonce/region patched by the packer)
; 4- mprotect it back to R+X
; 5- jump back to the ORIGINAL entry point of the host program
;
; The jump target is computed at runtime from our own address:
;       original_entry_runtime = runtime(_start) + (orig_entry_vaddr - stub_vaddr)
; The constant delta (orig_entry_vaddr - stub_vaddr) is known only to the
; C packer, so we assemble a recognizable 8-byte placeholder here and the
; C side patches it in before writing `woody`.

BITS 64
default rel

%define SYS_write    1
%define SYS_mprotect 10
%define PROT_READ    1
%define PROT_WRITE   2
%define PROT_EXEC    4
%define PAGE         0x1000

; ChaCha quarter-round on working-state dwords at [rsp + 4*idx]
%macro QR 4
	mov   eax, [rsp + 4*%1]
	add   eax, [rsp + 4*%2]
	mov   [rsp + 4*%1], eax
	mov   edx, [rsp + 4*%4]
	xor   edx, eax
	rol   edx, 16
	mov   [rsp + 4*%4], edx
	mov   ecx, [rsp + 4*%3]
	add   ecx, edx
	mov   [rsp + 4*%3], ecx
	mov   eax, [rsp + 4*%2]
	xor   eax, ecx
	rol   eax, 12
	mov   [rsp + 4*%2], eax
	mov   eax, [rsp + 4*%1]
	add   eax, [rsp + 4*%2]
	mov   [rsp + 4*%1], eax
	mov   edx, [rsp + 4*%4]
	xor   edx, eax
	rol   edx, 8
	mov   [rsp + 4*%4], edx
	mov   ecx, [rsp + 4*%3]
	add   ecx, edx
	mov   [rsp + 4*%3], ecx
	mov   eax, [rsp + 4*%2]
	xor   eax, ecx
	rol   eax, 7
	mov   [rsp + 4*%2], eax
%endmacro

; SSE2 ChaCha20 (4 columns at a time, state lives in xmm0..xmm3)
; rotate each dword lane of %1 left by %2 bits, scratch xmm %3
%macro ROTL 3
	movdqa  %3, %1
	pslld   %1, %2
	psrld   %3, 32-%2
	por     %1, %3
%endmacro

; one full quarter-round across all: a=%1 b=%2 c=%3 d=%4, scratch=%5
%macro CHACHA_QR 5
	paddd   %1, %2
	pxor    %4, %1
	ROTL    %4, 16, %5
	paddd   %3, %4
	pxor    %2, %3
	ROTL    %2, 12, %5
	paddd   %1, %2
	pxor    %4, %1
	ROTL    %4, 8, %5
	paddd   %3, %4
	pxor    %2, %3
	ROTL    %2, 7, %5
%endmacro

_start:
	cld
	push    rbx
	push    rdx                     ; rdx = rtld_fini, must survive to host _start
	push    r12
	push    r13
	push    r14
	push    r15
	sub     rsp, 128                ; [rsp+0..63]=working state, [rsp+64..127]=initial

	; write(1, msg, msg_len)
	mov     rax, SYS_write
	mov     rdi, 1
	lea     rsi, [rel msg]
	mov     rdx, msg_len
	syscall

	; initial ChaCha state at rsp+64
	mov     dword [rsp+64+0*4], 0x61707865
	mov     dword [rsp+64+1*4], 0x3320646e
	mov     dword [rsp+64+2*4], 0x79622d32
	mov     dword [rsp+64+3*4], 0x6b206574
	lea     rsi, [rel key]
	lea     rdi, [rsp+64+4*4]       ; words 4..11 = key
	mov     ecx, 8
	rep     movsd
	mov     dword [rsp+64+12*4], 0  ; word 12 = block counter
	lea     rsi, [rel nonce]
	lea     rdi, [rsp+64+13*4]      ; words 13..15 = nonce
	mov     ecx, 3
	rep     movsd

	; region runtime address and length
	lea     rbx, [rel _start]
	mov     r12, rbx
	add     r12, [rel region_delta] ; r12 = region start (advances)
	mov     r13, [rel region_len]   ; r13 = remaining bytes

	; mprotect(page_down(start), round_up(off+len), RW)
	mov     rdi, r12
	and     rdi, -PAGE
	mov     rsi, r12
	sub     rsi, rdi
	add     rsi, r13
	add     rsi, PAGE-1
	and     rsi, -PAGE
	mov     r14, rdi                ; save aligned start/len for the restore
	mov     r15, rsi
	mov     rdx, PROT_READ | PROT_WRITE
	mov     rax, SYS_mprotect
	syscall

	; ----- decrypt -----
	; Each pass turns the initial state at [rsp+64] into 64 keystream bytes at
	; [rsp], which the shared tail XORs into the code.
.block:
	test    r13, r13
	jz      .done
%ifdef USE_SSE2
	movdqu  xmm0, [rsp+64]          ; load initial state (4 rows) into xmm0..3
	movdqu  xmm1, [rsp+64+16]
	movdqu  xmm2, [rsp+64+32]
	movdqu  xmm3, [rsp+64+48]
	movdqa  xmm4, xmm0              ; keep originals for the feed-forward add
	movdqa  xmm5, xmm1
	movdqa  xmm6, xmm2
	movdqa  xmm7, xmm3
	mov     r8d, 10                 ; 10 double-rounds
.rounds:
	CHACHA_QR xmm0, xmm1, xmm2, xmm3, xmm8   ; column round
	pshufd  xmm1, xmm1, 0x39        ; rotate rows into diagonals
	pshufd  xmm2, xmm2, 0x4E
	pshufd  xmm3, xmm3, 0x93
	CHACHA_QR xmm0, xmm1, xmm2, xmm3, xmm8   ; diagonal round
	pshufd  xmm1, xmm1, 0x93        ; rotate rows back
	pshufd  xmm2, xmm2, 0x4E
	pshufd  xmm3, xmm3, 0x39
	dec     r8d
	jnz     .rounds
	paddd   xmm0, xmm4              ; working += initial
	paddd   xmm1, xmm5
	paddd   xmm2, xmm6
	paddd   xmm3, xmm7
	movdqu  [rsp], xmm0             ; serialize keystream (little-endian lanes)
	movdqu  [rsp+16], xmm1
	movdqu  [rsp+32], xmm2
	movdqu  [rsp+48], xmm3
%else
	lea     rsi, [rsp+64]           ; copy initial -> working
	lea     rdi, [rsp]
	mov     ecx, 16
	rep     movsd
	mov     r8d, 10                 ; 10 double-rounds
.rounds:
	QR 0,4,8,12
	QR 1,5,9,13
	QR 2,6,10,14
	QR 3,7,11,15
	QR 0,5,10,15
	QR 1,6,11,12
	QR 2,7,8,13
	QR 3,4,9,14
	dec     r8d
	jnz     .rounds
	xor     ecx, ecx                ; working[i] += initial[i]
.add_state:
	mov     eax, [rsp + rcx*4]
	add     eax, [rsp+64 + rcx*4]
	mov     [rsp + rcx*4], eax
	inc     ecx
	cmp     ecx, 16
	jb      .add_state
%endif
	mov     r9, 64                  ; n = min(64, remaining)
	cmp     r13, 64
	jae     .n_ok
	mov     r9, r13
.n_ok:
	xor     ecx, ecx                ; XOR keystream into the code
.xor_loop:
	mov     al, [rsp + rcx]
	xor     [r12 + rcx], al
	inc     ecx
	cmp     rcx, r9
	jb      .xor_loop
	add     r12, r9
	sub     r13, r9
	inc     dword [rsp+64+12*4]     ; counter++
	jmp     .block
.done:
	; mprotect back to R+X
	mov     rdi, r14
	mov     rsi, r15
	mov     rdx, PROT_READ | PROT_EXEC
	mov     rax, SYS_mprotect
	syscall

	add     rsp, 128
	pop     r15
	pop     r14
	pop     r13
	pop     r12
	pop     rdx
	pop     rbx

	; jump back to the host's original entry point
	lea     rax, [rel _start]
	add     rax, [rel entry_delta]
	jmp     rax

; parameter block (located and filled by the packer via the magic)
align 8
params:
	dq      0xDECAFFC0FFEEBABE      ; (+0)  magic
entry_delta:
	dq      0xDEADBEEFCAFEC0DE      ; (+8)  orig_entry  - stub_vaddr
region_delta:
	dq      0x1111111111111111      ; (+16) region_vaddr - stub_vaddr
region_len:
	dq      0x2222222222222222      ; (+24) region byte length
key:
	times 32 db 0                   ; (+32) ChaCha key
nonce:
	times 12 db 0                   ; (+64) ChaCha nonce
msg:
	db      0x2e,0x2e,0x2e,0x2e,'W','O','O','D','Y',0x2e,0x2e,0x2e,0x2e,0x0a
msg_len equ $ - msg
