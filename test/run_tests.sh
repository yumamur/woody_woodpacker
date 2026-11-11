#!/bin/sh
# End-to-end test: pack real fixtures, run them, and check the packed binary
# behaves exactly like the original. Covers dynamic PIE, no-PIE and static,
# against both the SSE2 and scalar ChaCha stubs, plus re-pack refusal and the
# compaction shrink. Exits non-zero if anything fails.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
PACKER="$ROOT/woody_woodpacker"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail=0
BANNER='^\.\.\.\.WOODY\.\.\.\.$'

cat > "$WORK/sample.c" <<'EOF'
#include <stdio.h>
int main(int argc, char **argv)
{
	(void)argv;
	printf("sample output argc=%d\n", argc);
	return 42;
}
EOF

build_fixtures()
{
	gcc         "$WORK/sample.c" -o "$WORK/t_pie"    2>/dev/null || return 1
	gcc -no-pie "$WORK/sample.c" -o "$WORK/t_nopie"  2>/dev/null || return 1
	gcc -static "$WORK/sample.c" -o "$WORK/t_static" 2>/dev/null || return 1
	# a copy with no PT_NOTE, to exercise the phdr-table-relocation path
	gcc "$ROOT/test/denote.c" -o "$WORK/denote" 2>/dev/null || return 1
	cp "$WORK/t_pie" "$WORK/t_nonote"
	"$WORK/denote" "$WORK/t_nonote" >/dev/null 2>&1 || return 1
}

# pack_and_check <variant-label> <fixture-path>
pack_and_check()
{
	v=$1; target=$2; name=$(basename "$target")
	( cd "$WORK" && "$PACKER" "$target" >/dev/null 2>&1 )
	if [ ! -f "$WORK/woody" ]; then
		echo "  [$v] $name: FAIL (no woody produced)"; fail=1; return
	fi
	chmod +x "$WORK/woody"
	"$target"      >"$WORK/ref.txt" 2>&1; rrc=$?
	( cd "$WORK" && ./woody ) >"$WORK/got.txt" 2>&1; grc=$?
	ref=$(cat "$WORK/ref.txt")
	got=$(grep -v "$BANNER" "$WORK/got.txt")
	if [ "$ref" = "$got" ] && [ "$rrc" = "$grc" ]; then
		echo "  [$v] $name: ok (exit $grc)"
	else
		echo "  [$v] $name: FAIL (exit $rrc vs $grc)"
		echo "       ref=[$ref] got=[$got]"; fail=1
	fi
	mv "$WORK/woody" "$WORK/woody_$name"
}

for v in "-DUSE_SSE2" ""; do
	label=${v:-scalar}; [ "$v" = "-DUSE_SSE2" ] && label=sse2
	echo "=== stub variant: $label ==="
	make clean >/dev/null 2>&1
	if ! make STUBDEF="$v" >/dev/null 2>&1; then
		echo "  build FAILED"; fail=1; continue
	fi
	build_fixtures || { echo "  fixture build FAILED"; fail=1; continue; }
	for t in t_pie t_nopie t_static t_nonote; do pack_and_check "$label" "$WORK/$t"; done

	# re-pack must be refused
	if "$PACKER" "$WORK/woody_t_static" >/dev/null 2>&1; then
		echo "  [$label] re-pack: FAIL (not refused)"; fail=1
	else
		echo "  [$label] re-pack: ok (refused)"
	fi

	# the static binary must actually shrink
	o=$(stat -c%s "$WORK/t_static"); p=$(stat -c%s "$WORK/woody_t_static")
	if [ "$p" -lt "$o" ]; then
		echo "  [$label] shrink: ok ($o -> $p, $((100 * p / o))%)"
	else
		echo "  [$label] shrink: FAIL ($o -> $p)"; fail=1
	fi
done

# 32-bit packing (fixture built with nasm + ld, no -m32 C toolchain needed).
# The 32-bit stub has no STUBDEF variants, so it is checked once.
echo "=== 32-bit ==="
if nasm -f elf32 "$ROOT/test/sample32.asm" -o "$WORK/s32.o" 2>/dev/null \
	&& ld -m elf_i386 "$WORK/s32.o" -o "$WORK/t32" 2>/dev/null \
	&& ( "$WORK/t32" >/dev/null 2>&1; [ $? -eq 42 ] ); then
	pack_and_check "elf32" "$WORK/t32"
else
	echo "  skipped (no working 32-bit build/run in this environment)"
fi

# PE (.exe) packing, both classes. Each fixture is an import-free .exe
# assembled with nasm that exits 42; the packed copy must still exit 42 under
# wine, proving the PE stub decrypts, decompresses and transfers control to the
# host entry. Needs wine (which runs both x86 and x64 PEs).
# pe_check <label> <asm-fixture>
pe_check()
{
	v=$1; src=$2
	if ! nasm -f bin "$src" -o "$WORK/pe.exe" 2>/dev/null \
		|| ! ( WINEDEBUG=-all wine "$WORK/pe.exe" >/dev/null 2>&1; [ $? -eq 42 ] )
	then
		echo "  [$v] skipped (fixture did not build/run)"; return
	fi
	rm -f "$WORK/woody"
	( cd "$WORK" && "$PACKER" pe.exe >/dev/null 2>&1 )
	if [ -f "$WORK/woody" ] \
		&& ( WINEDEBUG=-all wine "$WORK/woody" >/dev/null 2>&1; [ $? -eq 42 ] )
	then
		echo "  [$v] ok (exit 42)"
	else
		echo "  [$v] FAIL (packed copy did not exit 42)"; fail=1
	fi
	# re-pack must be refused (distinct name -> exercises .woody detection)
	cp "$WORK/woody" "$WORK/packed.exe" 2>/dev/null
	if ( cd "$WORK" && "$PACKER" packed.exe >/dev/null 2>&1 ); then
		echo "  [$v] re-pack: FAIL (not refused)"; fail=1
	else
		echo "  [$v] re-pack: ok (refused)"
	fi
}

echo "=== PE (.exe) ==="
if command -v wine >/dev/null 2>&1; then
	pe_check pe64 "$ROOT/test/petest64.asm"
	pe_check pe32 "$ROOT/test/petest32.asm"
else
	echo "  skipped (no wine in this environment)"
fi

# parameterized key (-k): supplied key is used verbatim and echoed, woody still
# runs identically, and malformed keys are rejected.
echo "=== parameterized key (-k) ==="
KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
rm -f "$WORK/woody"
out=$( cd "$WORK" && "$PACKER" -k "$KEY" t_pie 2>/dev/null )
echoed=$(echo "$out" | sed -n 's/^key_value: //p')
if [ "$echoed" = "$(echo "$KEY" | tr 'a-f' 'A-F')" ] && [ -f "$WORK/woody" ]; then
	chmod +x "$WORK/woody"
	ref=$("$WORK/t_pie" 2>&1); rrc=$?
	( cd "$WORK" && ./woody ) >"$WORK/kgot.txt" 2>&1; grc=$?
	got=$(grep -v "$BANNER" "$WORK/kgot.txt")
	if [ "$ref" = "$got" ] && [ "$rrc" = "$grc" ]; then
		echo "  supplied key used + woody runs: ok (exit $grc)"
	else
		echo "  supplied key: FAIL (exit $rrc vs $grc, ref=[$ref] got=[$got])"; fail=1
	fi
else
	echo "  supplied key: FAIL (echoed=[$echoed])"; fail=1
fi
for badk in abcdef "$(printf 'z%.0s' $(seq 64))"; do
	if ( cd "$WORK" && "$PACKER" -k "$badk" t_pie >/dev/null 2>&1 ); then
		echo "  bad key [$badk]: FAIL (not rejected)"; fail=1
	else
		echo "  bad key (len/charset): ok (rejected)"
	fi
done

# optional anti-debug (-a): the ELF stub prints the WOODY banner on a normal
# run but suppresses it when traced, while output and exit stay identical either
# way. Checked for both widths; the traced half needs strace (ptrace allowed).
# antidbg_check <label> <fixture>
antidbg_check()
{
	v=$1; target=$2
	[ -f "$target" ] || { echo "  [$v] skipped (no fixture)"; return; }
	rm -f "$WORK/woody"
	( cd "$WORK" && "$PACKER" -a "$target" >/dev/null 2>&1 )
	if [ ! -f "$WORK/woody" ]; then
		echo "  [$v] FAIL (no woody produced)"; fail=1; return
	fi
	chmod +x "$WORK/woody"
	ref=$("$target" 2>&1); rrc=$?
	# (1) untraced: banner MUST be present, behaviour identical
	( cd "$WORK" && ./woody ) >"$WORK/a_norm.txt" 2>&1; grc=$?
	got=$(grep -v "$BANNER" "$WORK/a_norm.txt")
	if grep -q "$BANNER" "$WORK/a_norm.txt" \
		&& [ "$ref" = "$got" ] && [ "$rrc" = "$grc" ]; then
		echo "  [$v] untraced: banner shown, runs ok (exit $grc)"
	else
		echo "  [$v] untraced: FAIL (banner/exit $rrc vs $grc, got=[$got])"; fail=1
	fi
	# (2) traced: banner MUST be suppressed, behaviour still identical
	if command -v strace >/dev/null 2>&1; then
		( cd "$WORK" && strace -f -o /dev/null ./woody ) >"$WORK/a_trace.txt" 2>&1
		trc=$?
		got=$(grep -v "$BANNER" "$WORK/a_trace.txt")
		if ! grep -q "$BANNER" "$WORK/a_trace.txt" \
			&& [ "$ref" = "$got" ] && [ "$rrc" = "$trc" ]; then
			echo "  [$v] traced:   banner suppressed, runs ok (exit $trc)"
		else
			echo "  [$v] traced:   FAIL (banner/exit $rrc vs $trc, got=[$got])"; fail=1
		fi
	else
		echo "  [$v] traced:   skipped (no strace)"
	fi
}

echo "=== anti-debug (-a) ==="
antidbg_check "elf64" "$WORK/t_pie"
antidbg_check "elf32" "$WORK/t32"

# non-executables must be refused (shared library, relocatable .o)
echo "=== rejects non-executables ==="
gcc -shared -fPIC "$WORK/sample.c" -o "$WORK/libsample.so" 2>/dev/null
gcc -c "$WORK/sample.c" -o "$WORK/sample.o" 2>/dev/null
for bad in libsample.so sample.o; do
	rm -f "$WORK/woody"
	if ( cd "$WORK" && "$PACKER" "$bad" >/dev/null 2>&1 ) || [ -f "$WORK/woody" ]; then
		echo "  $bad: FAIL (not rejected)"; fail=1
	else
		echo "  $bad: ok (rejected)"
	fi
done

# leave the tree built with the default (SSE2) stub
make clean >/dev/null 2>&1; make >/dev/null 2>&1

echo
if [ "$fail" -eq 0 ]; then echo "ALL END-TO-END TESTS PASS"; else echo "SOME TESTS FAILED"; fi
exit "$fail"
