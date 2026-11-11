; Minimal, import-free PE32 (x86) test fixture, assembled with `nasm -f bin`.
; Entry sets eax = 42 and returns, so `wine petest32.exe; echo $?` prints 42.
; The PE32 optional header differs from PE32+ by a 32-bit ImageBase, the extra
; BaseOfData field, and 32-bit stack/heap reserves.

BITS 32

dos:
	db      'MZ'
	times   0x3c-($-dos) db 0
	dd      0x40                    ; e_lfanew -> PE header

nt:
	dd      0x00004550              ; "PE\0\0"
	; --- COFF file header ---
	dw      0x014c                  ; Machine = i386
	dw      1                       ; NumberOfSections
	dd      0                       ; TimeDateStamp
	dd      0                       ; PointerToSymbolTable
	dd      0                       ; NumberOfSymbols
	dw      opt_end - opt           ; SizeOfOptionalHeader
	dw      0x102                   ; EXECUTABLE_IMAGE | 32BIT_MACHINE
opt:
	dw      0x010b                  ; PE32 magic
	db      0, 0                    ; linker version
	dd      0x200                   ; SizeOfCode
	dd      0                       ; SizeOfInitializedData
	dd      0                       ; SizeOfUninitializedData
	dd      0x1000                  ; AddressOfEntryPoint (RVA)
	dd      0x1000                  ; BaseOfCode
	dd      0x2000                  ; BaseOfData (PE32 only)
	dd      0x400000                ; ImageBase (32-bit)
	dd      0x1000                  ; SectionAlignment
	dd      0x200                   ; FileAlignment
	dw      4, 0                    ; OS version
	dw      0, 0                    ; image version
	dw      4, 0                    ; subsystem version
	dd      0                       ; Win32VersionValue
	dd      0x2000                  ; SizeOfImage
	dd      0x200                   ; SizeOfHeaders
	dd      0                       ; CheckSum
	dw      3                       ; Subsystem = CONSOLE
	dw      0                       ; DllCharacteristics
	dd      0x100000                ; SizeOfStackReserve
	dd      0x1000                  ; SizeOfStackCommit
	dd      0x100000                ; SizeOfHeapReserve
	dd      0x1000                  ; SizeOfHeapCommit
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
