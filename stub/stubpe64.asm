; woody_woodpacker PE32+ (x64) runtime stub.
;
;   1. ChaCha20-decrypt the compressed blob in place
;   2. LZ4-decompress the blob into the host's original code region
;   3. jump to the host's original entry point
;
; Unlike the ELF stub there are NO system calls and NO Windows API calls: the
; packer marks this stub's own section RWX and flips the MEM_WRITE bit on the
; host's code section, so both the blob and the decompression destination are
; already writable when the loader hands us control. That keeps the stub pure,
; position-independent computation -- the ChaCha20 and LZ4 routines are the same
; as the ELF stub. (The trade-off is a writable+executable code section, which
; is exactly what a transparent educational packer does; a stealthier stub would
; resolve VirtualProtect via a PEB walk instead.)
;
; The Windows loader resolves the host's imports before calling the entry point,
; so by the time we jump to the original entry its IAT is already populated.
;
; Position-independent. The packer locates the parameter block by its 8-byte
; magic and fills in the RVA-based deltas, lengths, key and nonce. Every delta
; is a difference of RVAs, which is invariant under ASLR relocation.

BITS 64
default rel

%define PAGE 0x1000

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
%macro ROTL 3
	movdqa  %3, %1
	pslld   %1, %2
	psrld   %3, 32-%2
	por     %1, %3
%endmacro

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
	; preserve what the loader handed us (some entry points read rcx=PEB) and
	; the callee-saved registers we scribble on, then restore before the jump.
	push    rcx
	push    rdx
	push    r8
	push    r9
	push    rbx
	push    r12
	push    r13
	push    r14
	push    r15
	sub     rsp, 128                ; [rsp+0..63]=working state, [rsp+64..127]=initial

	; initial ChaCha state at rsp+64
	mov     dword [rsp+64+0*4], 0x61707865      ; constant (expa|nd 3|2-by|te k)
	mov     dword [rsp+64+1*4], 0x3320646e
	mov     dword [rsp+64+2*4], 0x79622d32
	mov     dword [rsp+64+3*4], 0x6b206574
	lea     rsi, [rel key]
	lea     rdi, [rsp+64+4*4]                   ; words 4..11 = key
	mov     ecx, 8
	rep     movsd
	mov     dword [rsp+64+12*4], 0              ; word 12 = block counter
	lea     rsi, [rel nonce]
	lea     rdi, [rsp+64+13*4]                  ; words 13..15 = nonce
	mov     ecx, 3
	rep     movsd

	; decrypt the blob in place (our section is RWX, so it is already writable)
	lea     rbx, [rel _start]
	mov     r12, rbx
	add     r12, [rel src_delta]    ; r12 = blob start (advances)
	mov     r13, [rel comp_len]     ; r13 = remaining compressed bytes
.block:
	test    r13, r13
	jz      .decrypted
%ifdef USE_SSE2
	movdqu  xmm0, [rsp+64]
	movdqu  xmm1, [rsp+64+16]
	movdqu  xmm2, [rsp+64+32]
	movdqu  xmm3, [rsp+64+48]
	movdqa  xmm4, xmm0
	movdqa  xmm5, xmm1
	movdqa  xmm6, xmm2
	movdqa  xmm7, xmm3
	mov     r8d, 10
.rounds:
	CHACHA_QR xmm0, xmm1, xmm2, xmm3, xmm8
	pshufd  xmm1, xmm1, 0x39
	pshufd  xmm2, xmm2, 0x4E
	pshufd  xmm3, xmm3, 0x93
	CHACHA_QR xmm0, xmm1, xmm2, xmm3, xmm8
	pshufd  xmm1, xmm1, 0x93
	pshufd  xmm2, xmm2, 0x4E
	pshufd  xmm3, xmm3, 0x39
	dec     r8d
	jnz     .rounds
	paddd   xmm0, xmm4
	paddd   xmm1, xmm5
	paddd   xmm2, xmm6
	paddd   xmm3, xmm7
	movdqu  [rsp], xmm0
	movdqu  [rsp+16], xmm1
	movdqu  [rsp+32], xmm2
	movdqu  [rsp+48], xmm3
%else
	lea     rsi, [rsp+64]
	lea     rdi, [rsp]
	mov     ecx, 16
	rep     movsd
	mov     r8d, 10
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
	xor     ecx, ecx
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
	xor     ecx, ecx
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
.decrypted:

	; --- LZ4-decompress blob -> host code region ---
	; the destination section was marked writable by the packer, so no
	; VirtualProtect is needed. rdi = src ptr, r9 = src end, rdx = dst ptr.
	lea     rbx, [rel _start]
	mov     r12, rbx
	add     r12, [rel region_delta] ; r12 = region (decompress destination)
	mov     rdi, rbx
	add     rdi, [rel src_delta]
	mov     r9, rdi
	add     r9, [rel comp_len]
	mov     rdx, r12
.lz_loop:
	cmp     rdi, r9
	jae     .lz_done
	movzx   r11, byte [rdi]         ; token
	inc     rdi
	mov     r8, r11
	shr     r8, 4                   ; literal length
	cmp     r8, 15
	jne     .lz_litcopy
.lz_litext:
	movzx   rax, byte [rdi]
	inc     rdi
	add     r8, rax
	cmp     rax, 255
	je      .lz_litext
.lz_litcopy:
	test    r8, r8
	jz      .lz_afterlit
.lz_litloop:
	mov     al, [rdi]
	mov     [rdx], al
	inc     rdi
	inc     rdx
	dec     r8
	jnz     .lz_litloop
.lz_afterlit:
	cmp     rdi, r9
	jae     .lz_done                ; final literals-only sequence
	movzx   rax, word [rdi]         ; 2-byte little-endian offset
	add     rdi, 2
	mov     rcx, rdx
	sub     rcx, rax                ; match source = dst - offset
	mov     r8, r11
	and     r8, 15                  ; match length nibble
	cmp     r8, 15
	jne     .lz_mgo
.lz_mext:
	movzx   rax, byte [rdi]
	inc     rdi
	add     r8, rax
	cmp     rax, 255
	je      .lz_mext
.lz_mgo:
	add     r8, 4                   ; += MINMATCH
.lz_mloop:
	mov     al, [rcx]
	mov     [rdx], al
	inc     rcx
	inc     rdx
	dec     r8
	jnz     .lz_mloop
	jmp     .lz_loop
.lz_done:

	add     rsp, 128
	pop     r15
	pop     r14
	pop     r13
	pop     r12
	pop     rbx
	pop     r9
	pop     r8
	pop     rdx
	pop     rcx

	; --- jump to the host's original entry point ---
	lea     rax, [rel _start]
	add     rax, [rel entry_delta]
	jmp     rax

; ---- parameter block (located and filled by the packer via the magic) ----
align 8
params:
	dq      0xDECAFFC0FFEEBABE      ; magic                        (+0)
entry_delta:
	dq      0xDEADBEEFCAFEC0DE      ; orig_entry_rva - stub_rva     (+8)
region_delta:
	dq      0x1111111111111111      ; region_rva     - stub_rva     (+16)
region_len:
	dq      0x2222222222222222      ; decompressed region length L  (+24)
src_delta:
	dq      0x3333333333333333      ; blob_rva       - stub_rva     (+32)
comp_len:
	dq      0x4444444444444444      ; compressed+encrypted length   (+40)
key:
	times 32 db 0                   ; ChaCha key                    (+48)
nonce:
	times 12 db 0                   ; ChaCha nonce                  (+80)
