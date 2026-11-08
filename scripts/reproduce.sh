#!/usr/bin/env bash
# reproduce.sh: Regenera la evidencia del laboratorio y verifica resultados.
# Requisitos: binutils, file, gdb, python3. Opcional: GHIDRA_HOME para el decompilado headless.
# Uso (desde la raíz del repo):  ./scripts/reproduce.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/binaries"; EV="$ROOT/docs/evidence/reverse"; RAW="$EV/raw"; GDBS="$ROOT/scripts/gdb"
mkdir -p "$RAW"; cd "$BIN"; chmod +x crackme_*
FILES="crackme_level1 crackme_level2 crackme_level2_stripped"

echo "[1/5] Verificando integridad (SHA-256 publicados en la guía)"
sha256sum -c <<'EOF' || { echo "!! Hash distinto: no es el material original"; exit 1; }
61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c  crackme_level1
8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5  crackme_level2
c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3  crackme_level2_stripped
EOF

echo "[2/5] Generando baseline.txt"
{
  echo "# FDSI · Lab 04 Parte 2 · Baseline forense"
  echo "# Generado: $(date -u +%FT%TZ) | Host: $(uname -srm)"
  echo "# Herramientas: $(file --version|head -1) | $(readelf --version|head -1) | $(gdb --version|head -1)"
  echo; echo "===== file ====="; file $FILES
  echo; echo "===== sha256sum ====="; sha256sum $FILES
  echo; echo "===== Verificación contra hashes publicados en la guía ====="
  printf '%s  %s\n' 61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c crackme_level1 \
    8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5 crackme_level2 \
    c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3 crackme_level2_stripped | sha256sum -c
  echo; echo "===== ls -l ====="; ls -l crackme_*
  for f in $FILES; do echo; echo "===== readelf -h $f ====="; readelf -h "$f"; done
  for f in $FILES; do
    echo; echo "===== readelf -S $f (resumen de secciones) ====="; readelf -SW "$f" | grep -E '^\s+\['
    echo; echo "===== readelf -d $f | NEEDED ====="; readelf -d "$f" | grep NEEDED
    echo; echo "===== nm $f (símbolos definidos en .text/.rodata) ====="; nm "$f" 2>&1 | grep -E ' [TtRrDd] |no symbols'
  done
  echo; echo "===== checksec manual (protecciones) ====="
  for f in $FILES; do
    t=$(readelf -h "$f" | awk '/Type:/{print $2}'); nx=$(readelf -lW "$f" | awk '/GNU_STACK/{print $7}')
    relro=$(readelf -lW "$f" | grep -c GNU_RELRO); can=$(nm -D "$f" 2>/dev/null | grep -c __stack_chk_fail)
    echo "$f: Type=$t (EXEC = sin PIE) | GNU_STACK flags=$nx | RELRO segs=$relro | stack canary=$can"
  done
} > "$EV/baseline.txt" 2>&1

echo "[3/5] Evidencia estática (strings / objdump)"
strings -n 5 -t x crackme_level1 > "$RAW/level1_strings.txt"
objdump -d -M intel crackme_level1 > "$RAW/level1_objdump.txt"
objdump -s -j .rodata crackme_level1 > "$RAW/level1_rodata.txt"
objdump -s -j .rodata crackme_level2 > "$RAW/level2_rodata.txt"
objdump -d -M intel crackme_level2_stripped > "$RAW/stripped_objdump.txt"

echo "[4/5] Sesiones GDB"
for s in 1 2 3 4; do gdb -q -batch -x "$GDBS/sesion$s.gdb" ./crackme_level2 > "$RAW/gdb_session$s.txt" 2>&1; done
gdb -q -batch -x "$GDBS/sesion5.gdb"  ./crackme_level2_stripped > "$RAW/gdb_session5.txt"  2>&1
gdb -q -batch -x "$GDBS/sesion5b.gdb" ./crackme_level2_stripped > "$RAW/gdb_session5b.txt" 2>&1

if [[ -n "${GHIDRA_HOME:-}" ]]; then
  echo "    Ghidra headless ($GHIDRA_HOME)"
  P=$(mktemp -d)
  for f in $FILES; do
    "$GHIDRA_HOME/support/analyzeHeadless" "$P" fdsi -import "$BIN/$f" -overwrite \
      -scriptPath "$ROOT/scripts" -postScript ExportDecomp.java "$RAW/ghidra_$f.c" >/dev/null 2>&1
  done
fi

echo "[5/5] Verificando claves y FLAGs"
KEY2=$(python3 "$ROOT/scripts/solve_level2.py" crackme_level2_stripped | awk -F': ' '/reconstruida/{print $2}')
ok=0
./crackme_level1 REDTEAM-101 | grep -q 'FLAG{strings_are_evidence}' && echo "  Nivel 1  OK  REDTEAM-101" || ok=1
./crackme_level2 "$KEY2"        | grep -q 'FLAG{ghidra_plus_gdb}'      && echo "  Nivel 2  OK  $KEY2"      || ok=1
./crackme_level2_stripped "$KEY2" | grep -q 'FLAG{ghidra_plus_gdb}'    && echo "  Boss     OK  $KEY2"      || ok=1
[[ $ok -eq 0 ]] && echo "Todo verificado." || { echo "!! Alguna verificación falló"; exit 1; }
