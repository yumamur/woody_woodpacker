; Minimal, import-free PE32+ (x64) test fixture, assembled with `nasm -f bin`.
; The entry point sets eax = 42 and returns; the initial thread's return value
; becomes the process exit code, so `wine petest64.exe; echo $?` prints 42.
; Used to prove the woody PE stub decrypts/decompresses and transfers control to
; the host's real entry (a packed copy must still exit 42).

BITS 64

dos:
	db      'MZ'
	times   0x3c-($-dos) db 0
	dd      0x40                    ; e_lfanew -> PE header

nt:
	dd      0x00004550              ; "PE\0\0"
	; --- COFF file header ---
	dw      0x8664                  ; Machine = AMD64
	dw      1                       ; NumberOfSections
	dd      0                       ; TimeDateStamp
	dd      0                       ; PointerToSymbolTable
	dd      0                       ; NumberOfSymbols
	dw      opt_end - opt           ; SizeOfOptionalHeader
	dw      0x22                    ; EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
opt:
	dw      0x020b                  ; PE32+ magic
	db      0, 0                    ; linker version
	dd      0x200                   ; SizeOfCode
	dd      0                       ; SizeOfInitializedData
	dd      0                       ; SizeOfUninitializedData
	dd      0x1000                  ; AddressOfEntryPoint (RVA)
	dd      0x1000                  ; BaseOfCode
	dq      0x140000000             ; ImageBase
	dd      0x1000                  ; SectionAlignment
	dd      0x200                   ; FileAlignment
	dw      6, 0                    ; OS version
	dw      0, 0                    ; image version
	dw      6, 0                    ; subsystem version
	dd      0                       ; Win32VersionValue
	dd      0x2000                  ; SizeOfImage
	dd      0x200                   ; SizeOfHeaders
	dd      0                       ; CheckSum
	dw      3                       ; Subsystem = CONSOLE
	dw      0                       ; DllCharacteristics
	dq      0x100000                ; SizeOfStackReserve
	dq      0x1000                  ; SizeOfStackCommit
	dq      0x100000                ; SizeOfHeapReserve
	dq      0x1000                  ; SizeOfHeapCommit
	dd      0                       ; LoaderFlags
	dd      16                      ; NumberOfRvaAndSizes
	times   16 dq 0                 ; empty data directories (no imports)
opt_end:
	; --- section table ---
	db      '.text', 0, 0, 0        ; Name (8 bytes)
	dd      0x200                    ; VirtualSize
	dd      0x1000                   ; VirtualAddress
	dd      0x200                    ; SizeOfRawData
	dd      0x200                    ; PointerToRawData
	dd      0                        ; PointerToRelocations
	dd      0                        ; PointerToLinenumbers
	dw      0                        ; NumberOfRelocations
	dw      0                        ; NumberOfLinenumbers
	dd      0x60000020               ; CODE | EXECUTE | READ

	times   0x200-($-dos) db 0       ; pad headers to SizeOfHeaders

code:                                ; file 0x200, RVA 0x1000
	mov     eax, 42
	ret
	times   0x200-($-code) db 0       ; pad section raw data to FileAlignment
