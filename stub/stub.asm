; woody_woodpacker runtime stub (compressing variant).
;
;   1. write(1, "....WOODY....\n", 14)
;   2. mprotect the blob's own pages writable (the stub's segment is mapped
;      R+X, not writable, so no page is ever both writable and executable)
;   3. ChaCha20-decrypt the compressed blob in place
;   4. mprotect the destination code region writable
;   5. LZ4-decompress the blob into the region (source and destination are in
;      different segments, so the expansion never overlaps its input)
;   6. mprotect the region back to R+X
;   7. jump to the host's original entry point
;
; Position-independent. The packer locates the parameter block by its 8-byte
; magic and fills in the deltas, lengths, key and nonce.

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
	push    rbx
	push    rdx                     ; rdx = rtld_fini, must survive to host _start
	push    r12
	push    r13
	push    r14
	push    r15
	sub     rsp, 128                ; [rsp+0..63]=working state, [rsp+64..127]=initial

	; --- anti-analysis (optional, enabled by -a flag) ---
	movzx   eax, byte [rel antidbg]
	test    al, al
	jz      .banner                 ; feature off -> always print the banner
	sub     rsp, 2048               ; scratch buffer for the status file
	lea     rdi, [rel proc_status]
	xor     esi, esi                ; O_RDONLY
	mov     eax, 2                  ; SYS_open
	syscall
	test    rax, rax
	js      .banner_free            ; can't open -> print the banner
	mov     r8, rax                 ; fd
	mov     rdi, rax
	mov     rsi, rsp
	mov     edx, 2048
	xor     eax, eax                ; SYS_read
	syscall
	mov     r9, rax                 ; bytes read
	mov     rdi, r8
	mov     eax, 3                  ; SYS_close
	syscall
	test    r9, r9
	jle     .banner_free            ; read nothing -> print the banner
	mov     r10, rsp                ; p = buf
	mov     r11, rsp
	add     r11, r9                 ; end = buf + n
.ad_scan:
	mov     rax, r11
	sub     rax, r10
	cmp     rax, 11                 ; need "TracerPid:" + one digit
	jb      .banner_free            ; field not found -> print the banner
	mov     rsi, r10
	lea     rdi, [rel tracer_str]
	mov     ecx, 10
	repe    cmpsb                   ; DF=0 (cld above)
	jne     .ad_next
	mov     rsi, r10
	add     rsi, 10                 ; first char after "TracerPid:"
.ad_ws:
	mov     al, [rsi]
	cmp     al, 0x20                ; space
	je      .ad_wsadv
	cmp     al, 0x09                ; tab
	jne     .ad_digit
.ad_wsadv:
	inc     rsi
	jmp     .ad_ws
.ad_digit:
	cmp     al, '0'
	jne     .ad_traced              ; non-zero TracerPid -> debugger present
	jmp     .banner_free            ; '0' -> not traced -> print
.ad_next:
	inc     r10
	jmp     .ad_scan
.ad_traced:
	add     rsp, 2048
	jmp     .after_banner           ; traced: skip the banner entirely
.banner_free:
	add     rsp, 2048               ; release scratch, then print
.banner:
	; ....WOODY....
	mov     rax, SYS_write
	mov     rdi, 1
	lea     rsi, [rel msg]
	mov     rdx, msg_len
	syscall
.after_banner:

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

	; make the blob's own pages writable for in-place decryption
	; the segment is mapped R+X; mprotect to RW (not X) so no page is ever W+X
	lea     rbx, [rel _start]
	mov     rdi, rbx
	add     rdi, [rel src_delta]    ; blob start (page-aligned by the packer)
	and     rdi, -PAGE
	mov     rsi, [rel comp_len]
	add     rsi, PAGE-1
	and     rsi, -PAGE
	mov     rdx, PROT_READ | PROT_WRITE
	mov     rax, SYS_mprotect
	syscall

	; decrypt the blob in place
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

	; --- mprotect(page_down(region), round_up(off+len), RW) ---
	lea     rbx, [rel _start]
	mov     r12, rbx
	add     r12, [rel region_delta] ; r12 = region start (decompress destination)
	mov     r13, [rel region_len]   ; r13 = decompressed length L
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

	; --- LZ4-decompress blob -> region ---
	; rdi = src ptr, r9 = src end, rdx = dst ptr (advances). r11 = token.
	lea     rbx, [rel _start]
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

	; --- mprotect region back to R+X ---
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

	; --- jump to the host's original entry point ---
	lea     rax, [rel _start]
	add     rax, [rel entry_delta]
	jmp     rax

; ---- parameter block (located and filled by the packer via the magic) ----
align 8
params:
	dq      0xDECAFFC0FFEEBABE      ; magic                        (+0)
entry_delta:
	dq      0xDEADBEEFCAFEC0DE      ; orig_entry   - stub_vaddr     (+8)
region_delta:
	dq      0x1111111111111111      ; region_vaddr - stub_vaddr     (+16)
region_len:
	dq      0x2222222222222222      ; decompressed region length L  (+24)
src_delta:
	dq      0x3333333333333333      ; blob_vaddr   - stub_vaddr     (+32)
comp_len:
	dq      0x4444444444444444      ; compressed+encrypted length   (+40)
key:
	times 32 db 0                   ; ChaCha key                    (+48)
nonce:
	times 12 db 0                   ; ChaCha nonce                  (+80)
antidbg:
	db      0                       ; 1 = run the TracerPid check   (+92)
msg:
	db      0x2e,0x2e,0x2e,0x2e,'W','O','O','D','Y',0x2e,0x2e,0x2e,0x2e,0x0a
msg_len equ $ - msg
proc_status:
	db      "/proc/self/status", 0
tracer_str:
	db      "TracerPid:"
