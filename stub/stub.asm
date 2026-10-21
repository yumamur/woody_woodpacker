; 1- write(1, "....WOODY....\n", 14)
; 2- jump back to the ORIGINAL entry point of the host program
;
; The jump target is computed at runtime from our own address:
;       original_entry_runtime = runtime(_start) + (orig_entry_vaddr - stub_vaddr)
; The constant delta (orig_entry_vaddr - stub_vaddr) is known only to the
; C packer, so we assemble a recognizable 8-byte placeholder here and the
; C side patches it in before writing `woody`.

BITS 64
default rel

_start:
    push    rax
    push    rdi
    push    rsi
    push    rdx
    push    rcx
    push    r11

    ; write(1, msg, msg_len)
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rel msg]   ; runtime address of the string
    mov     rdx, msg_len
    syscall

    pop     r11
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi
    pop     rax

    ; jump back to the host's original entry point
    lea     rax, [rel _start]           ; runtime address of this stub
    mov     r11, 0xDEADBEEFCAFEC0DE
    add     rax, r11                    ; runtime address of original entry
    jmp     rax

msg:
    db      0x2e, 0x2e, 0x2e, 0x2e      ; "...."
    db      'W', 'O', 'O', 'D', 'Y'     ; "WOODY"
    db      0x2e, 0x2e, 0x2e, 0x2e      ; "...."
    db      0x0a                        ; "\n"
msg_len equ $ - msg
