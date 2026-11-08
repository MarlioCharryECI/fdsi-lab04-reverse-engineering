# FDSI · Lab 04 Parte 2: Reverse Engineering Challenge

Ruta alternativa **100 % local** del laboratorio Red Team vs. Blue Team: un CTF de ingeniería inversa sobre tres binarios ELF x86-64 entregados por el docente, analizados **sin código fuente**.

**Equipo:** Marlio José Charry Espitia · David Alejandro Patacón Henao
**Curso:** FDSI · 2026-2 · Escuela Colombiana de Ingeniería Julio Garavito
**Tag de entrega:** `lab-reverse-v1`

## Resultados

| Nivel | Binario | Clave | FLAG | Técnica |
|---|---|---|---|---|
| 1 · Recon | `crackme_level1` | `REDTEAM-101` | `FLAG{strings_are_evidence}` | `strings`, `objdump` |
| 2 · Decompile | `crackme_level2` | `FDSI-REVERSE-2026` | `FLAG{ghidra_plus_gdb}` | Ghidra + GDB |
| Boss · Stripped | `crackme_level2_stripped` | `FDSI-REVERSE-2026` | `FLAG{ghidra_plus_gdb}` | XREFs, flujo desde `entry`, firma en ensamblador |

**Algoritmo del Nivel 2:** `len(key) == 17` y `key[i] XOR K[i mod 4] == E[i]`, con `K = 23 51 17 6a`. Por lo tanto, `key[i] = E[i] XOR K[i mod 4]`.

## Cumplimiento de la guía

| Sección de la guía | Dónde está la evidencia |
|---|---|
| 0 · Preparación (`file`, SHA-256, `docs/evidence/reverse/`, sin código fuente) | [`baseline.txt`](docs/evidence/reverse/baseline.txt) · [Alcance y ética](#alcance-y-ética) |
| 1 · Baseline forense (arquitectura, linking, símbolos, por qué el hash) | [`baseline.txt`](docs/evidence/reverse/baseline.txt) · [`reverse-analysis.md` §1](reverse-analysis.md#1-preparación-y-baseline-forense) |
| 2 · Nivel 1: *Strings are evidence* | [`level1.md`](docs/evidence/reverse/level1.md) (hipótesis → evidencia → resultado, §7 por qué `strings` revela secretos) |
| 3 · Nivel 2: Ghidra (función, longitud, transformación, clave, captura con renombres) | [`level2.md`](docs/evidence/reverse/level2.md) (§3 renombres, §4 pseudocódigo propio, §5 inversión) |
| 4 · Confirmación dinámica con GDB (clave fallida y válida) | [`gdb.md`](docs/evidence/reverse/gdb.md) (sesiones 1–3, más bypass en la sesión 4) |
| 5 · Boss Level: qué borró `strip` y cómo se reencontró la validación | [`reverse-analysis.md` §5](reverse-analysis.md#5-boss-level-binario-sin-símbolos) · [`gdb.md` sesión 5](docs/evidence/reverse/gdb.md#sesión-5-boss-mismo-análisis-sin-símbolos) |
| 6 · Evidencia GitHub + tag `lab-reverse-v1` | Este repositorio |
| Preguntas de análisis (1–7) | [`reverse-analysis.md` §6](reverse-analysis.md#6-preguntas-de-análisis) |
| Cierre de 3 minutos | [`reverse-analysis.md` §9](reverse-analysis.md#9-síntesis-para-el-cierre) |
| Módulo opcional Burp Suite | [`burp.md`](docs/evidence/reverse/burp.md): procedimiento y comparación web vs. reverse |

## Cómo leer este repositorio

1. **[`reverse-analysis.md`](reverse-analysis.md)**: informe principal. Baseline, resumen de cada nivel, Boss Level, las 7 preguntas de análisis, las lecciones de desarrollo seguro y la síntesis para el cierre.
2. Evidencia por etapa:
   - [`docs/evidence/reverse/baseline.txt`](docs/evidence/reverse/baseline.txt): `file`, `sha256sum` (verificado), `readelf`, `nm`, protecciones
   - [`docs/evidence/reverse/level1.md`](docs/evidence/reverse/level1.md): hipótesis → evidencia → resultado
   - [`docs/evidence/reverse/level2.md`](docs/evidence/reverse/level2.md): proceso en Ghidra, renombres, **pseudocódigo propio**, inversión de la clave
   - [`docs/evidence/reverse/gdb.md`](docs/evidence/reverse/gdb.md): validación dinámica (clave fallida vs. válida, bypass de `eax`, stripped)
   - [`docs/evidence/reverse/burp.md`](docs/evidence/reverse/burp.md): módulo complementario Burp Suite
   - [`docs/evidence/reverse/screenshots/`](docs/evidence/reverse/screenshots/): capturas de Ghidra y de la terminal
   - [`docs/evidence/reverse/raw/`](docs/evidence/reverse/raw/): salidas completas sin editar (strings, objdump, decompilado de Ghidra, sesiones GDB)

## Estructura

```
.
├── README.md
├── reverse-analysis.md
├── binaries/                      # material original del docente (hashes verificados)
│   ├── crackme_level1
│   ├── crackme_level2
│   └── crackme_level2_stripped
├── scripts/
│   ├── reproduce.sh               # regenera la evidencia y verifica las FLAGs
│   ├── solve_level2.py            # reconstruye la clave leyendo K y E del ELF
│   ├── decode_level1_flag.py      # descifra la FLAG 1 desde los inmediatos (XOR 0x5a)
│   ├── ExportDecomp.java          # script Ghidra: exporta decompilado + XREFs de strings
│   ├── AnnotateStripped.java      # script Ghidra: renombres/comentarios en el binario stripped
│   └── gdb/sesion{1..5,5b}.gdb    # sesiones de GDB
└── docs/
    └── evidence/
        └── reverse/
            ├── baseline.txt
            ├── level1.md
            ├── level2.md
            ├── gdb.md
            ├── burp.md
            ├── raw/
            └── screenshots/
```

## Reproducir

Requisitos: Linux x86-64, `binutils`, `file`, `gdb`, `python3`. Ghidra es opcional.

```bash
sudo apt install -y binutils gdb file
./scripts/reproduce.sh
# con Ghidra (decompilado headless):
GHIDRA_HOME=/opt/ghidra_11.3.2_PUBLIC ./scripts/reproduce.sh
```

Salida esperada:

```text
  Nivel 1  OK  REDTEAM-101
  Nivel 2  OK  FDSI-REVERSE-2026
  Boss     OK  FDSI-REVERSE-2026
Todo verificado.
```

## Entorno usado

Ubuntu 24.04 x86-64 · GNU binutils 2.42 · file 5.45 · GNU gdb 15.1 · Ghidra 11.3.2 (release oficial, proyecto *Non-Shared*, análisis automático por defecto) · OpenJDK 21 · Python 3.

## Alcance y ética

- Solo se analizaron los crackmes académicos entregados por el docente para esta práctica, con hashes verificados contra la guía.
- No se abrió ni se solicitó el código fuente.
- Los binarios no contienen malware, persistencia ni funcionalidad destructiva (según la guía; el análisis tampoco encontró ninguna llamada de red, archivos ni procesos: solo `strlen`, `strcmp`, `puts`, `printf`, `putchar`).
- El módulo de Burp se limita al laboratorio asignado de PortSwigger Web Security Academy.
