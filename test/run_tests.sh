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
