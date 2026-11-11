; woody_woodpacker PE32 (x86) runtime stub.
;
; The i386 counterpart of stubpe64.asm: position-independent via a call/pop that
; recovers EIP (no RIP-relative addressing on x86-32), scalar ChaCha20, and the
; same LZ4 decompressor as the 32-bit ELF stub. Like the 64-bit PE stub it makes
; NO system calls and NO Windows API calls -- the packer marks this section RWX
; and flips MEM_WRITE on the host code section, so nothing needs VirtualProtect.
;
;   1. ChaCha20-decrypt the compressed blob in place
;   2. LZ4-decompress the blob into the host's original code region
;   3. jump to the host's original entry point
;
; EBP holds runtime(_start) throughout; every parameter is read at
; [ebp + field - _start]. Deltas are RVA differences (relocation-invariant).

BITS 32

; ChaCha quarter-round on working-state dwords at [esp + 4*idx]
%macro QR 4
	mov   eax, [esp + 4*%1]
	add   eax, [esp + 4*%2]
	mov   [esp + 4*%1], eax
	mov   edx, [esp + 4*%4]
	xor   edx, eax
	rol   edx, 16
	mov   [esp + 4*%4], edx
	mov   ecx, [esp + 4*%3]
	add   ecx, edx
	mov   [esp + 4*%3], ecx
	mov   eax, [esp + 4*%2]
	xor   eax, ecx
	rol   eax, 12
	mov   [esp + 4*%2], eax
	mov   eax, [esp + 4*%1]
	add   eax, [esp + 4*%2]
	mov   [esp + 4*%1], eax
	mov   edx, [esp + 4*%4]
	xor   edx, eax
	rol   edx, 8
	mov   [esp + 4*%4], edx
	mov   ecx, [esp + 4*%3]
	add   ecx, edx
	mov   [esp + 4*%3], ecx
	mov   eax, [esp + 4*%2]
	xor   eax, ecx
	rol   eax, 7
	mov   [esp + 4*%2], eax
%endmacro

; stack frame: [esp+0..63] working state, [esp+64..127] initial state, locals.
%define F_PTR      128   ; blob/region cursor (advances)
%define F_REM      132   ; remaining bytes to decrypt
%define F_N        136   ; min(64, remaining)
%define F_SRCEND   140   ; LZ4 source end
%define FRAME      160

_start:
	push    ebx
	push    esi
	push    edi
	push    ebp
	call    .getbase
.getbase:
	pop     ebp
	sub     ebp, .getbase - _start  ; ebp = runtime(_start)
	sub     esp, FRAME

	; --- cursor = blob, remaining = comp_len ---
	mov     eax, [ebp + src_delta - _start]
	add     eax, ebp
	mov     [esp + F_PTR], eax
	mov     eax, [ebp + comp_len - _start]
	mov     [esp + F_REM], eax

	; --- initial ChaCha state at esp+64 ---
	mov     dword [esp+64+0*4], 0x61707865
	mov     dword [esp+64+1*4], 0x3320646e
	mov     dword [esp+64+2*4], 0x79622d32
	mov     dword [esp+64+3*4], 0x6b206574
	lea     esi, [ebp + key - _start]
	lea     edi, [esp+64+4*4]
	mov     ecx, 8
	rep     movsd
	mov     dword [esp+64+12*4], 0  ; block counter
	lea     esi, [ebp + nonce - _start]
	lea     edi, [esp+64+13*4]
	mov     ecx, 3
	rep     movsd

	; --- decrypt the blob in place, 64-byte block at a time ---
.block:
	mov     edi, [esp + F_REM]
	test    edi, edi
	jz      .decrypted
	lea     esi, [esp+64]           ; copy initial -> working
	mov     edi, esp
	mov     ecx, 16
	rep     movsd
	mov     ebx, 10                 ; 10 double-rounds
.rounds:
	QR 0,4,8,12
	QR 1,5,9,13
	QR 2,6,10,14
	QR 3,7,11,15
	QR 0,5,10,15
	QR 1,6,11,12
	QR 2,7,8,13
	QR 3,4,9,14
	dec     ebx
	jnz     .rounds
	xor     ecx, ecx                ; working[i] += initial[i]
.add_state:
	mov     eax, [esp + ecx*4]
	add     eax, [esp+64 + ecx*4]
	mov     [esp + ecx*4], eax
	inc     ecx
	cmp     ecx, 16
	jb      .add_state
	mov     edi, [esp + F_REM]      ; n = min(64, remaining)
	mov     eax, 64
	cmp     edi, 64
	jae     .n_ok
	mov     eax, edi
.n_ok:
	mov     [esp + F_N], eax
	mov     esi, [esp + F_PTR]
	xor     ecx, ecx                ; XOR keystream into the blob
.xor_loop:
	mov     al, [esp + ecx]
	xor     [esi + ecx], al
	inc     ecx
	cmp     ecx, [esp + F_N]
	jb      .xor_loop
	mov     eax, [esp + F_N]
	add     [esp + F_PTR], eax
	sub     [esp + F_REM], eax
	inc     dword [esp+64+12*4]     ; counter++
	jmp     .block
.decrypted:

	; --- LZ4-decompress blob -> region (destination already writable) ---
	; edi = src, esi = dst (region), ebx = token, [esp+F_SRCEND] = src end
	mov     esi, [ebp + region_delta - _start]
	add     esi, ebp                ; region start (decompress destination)
	mov     edi, [ebp + src_delta - _start]
	add     edi, ebp
	mov     eax, edi
	add     eax, [ebp + comp_len - _start]
	mov     [esp + F_SRCEND], eax
.lz_loop:
	mov     eax, [esp + F_SRCEND]
	cmp     edi, eax
	jae     .lz_done
	movzx   ebx, byte [edi]         ; token
	inc     edi
	mov     ecx, ebx
	shr     ecx, 4                  ; literal length
	cmp     ecx, 15
	jne     .lz_litcopy
.lz_litext:
	movzx   eax, byte [edi]
	inc     edi
	add     ecx, eax
	cmp     eax, 255
	je      .lz_litext
.lz_litcopy:
	test    ecx, ecx
	jz      .lz_afterlit
.lz_litloop:
	mov     al, [edi]
	mov     [esi], al
	inc     edi
	inc     esi
	dec     ecx
	jnz     .lz_litloop
.lz_afterlit:
	mov     eax, [esp + F_SRCEND]
	cmp     edi, eax
	jae     .lz_done                ; final literals-only sequence
	movzx   eax, word [edi]         ; 2-byte little-endian offset
	add     edi, 2
	mov     edx, esi
	sub     edx, eax                ; match source = dst - offset
	mov     ecx, ebx
	and     ecx, 15                 ; match length nibble
	cmp     ecx, 15
	jne     .lz_mgo
.lz_mext:
	movzx   eax, byte [edi]
	inc     edi
	add     ecx, eax
	cmp     eax, 255
	je      .lz_mext
.lz_mgo:
	add     ecx, 4                  ; += MINMATCH
.lz_mloop:
	mov     al, [edx]
	mov     [esi], al
	inc     edx
	inc     esi
	dec     ecx
	jnz     .lz_mloop
	jmp     .lz_loop
.lz_done:

	; --- jump to the host's original entry point ---
	mov     eax, [ebp + entry_delta - _start]
	add     eax, ebp                ; eax survives the pops below
	add     esp, FRAME
	pop     ebp
	pop     edi
	pop     esi
	pop     ebx
	jmp     eax

; ---- parameter block (located and filled by the packer via the magic) ----
align 8
params:
	dq      0xDECAFFC0FFEEBABE      ; magic                        (+0)
entry_delta:
	dd      0xDEADBEEF              ; orig_entry_rva - stub_rva     (+8)
region_delta:
	dd      0x11111111             ; region_rva     - stub_rva     (+12)
region_len:
	dd      0x22222222             ; decompressed region length L  (+16)
src_delta:
	dd      0x33333333             ; blob_rva       - stub_rva     (+20)
comp_len:
	dd      0x44444444             ; compressed+encrypted length   (+24)
key:
	times 32 db 0                   ; ChaCha key                   (+28)
nonce:
	times 12 db 0                   ; ChaCha nonce                 (+60)
