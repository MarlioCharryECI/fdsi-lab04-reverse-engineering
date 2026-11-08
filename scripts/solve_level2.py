#!/usr/bin/env python3
"""
solve_level2.py: Reconstruye la licencia de crackme_level2 / crackme_level2_stripped
a partir de los datos estáticos del ELF (sin ejecutar el binario).

Fundamento (ver docs/evidence/reverse/level2.md):
    validate_key acepta la entrada si, para todo i en [0, 17):
        (input[i] XOR K[i % 4]) == EXPECTED[i]
    Como XOR es reversible:
        input[i] = EXPECTED[i] XOR K[i % 4]

Las direcciones virtuales salen del análisis en Ghidra/objdump:
    K        -> 0x40208b  (4 bytes,  'k.1' en el binario con símbolos)
    EXPECTED -> 0x402090  (17 bytes, 'expected.0')
    longitud -> 0x11 = 17 (constante en 'mov QWORD PTR [rbp-0x18],0x11')

Uso:
    python3 scripts/solve_level2.py binaries/crackme_level2
    python3 scripts/solve_level2.py binaries/crackme_level2_stripped
"""
import struct
import sys

K_VADDR, K_LEN = 0x40208B, 4
EXP_VADDR, EXP_LEN = 0x402090, 17


def read_vaddr(elf: bytes, vaddr: int, size: int) -> bytes:
    """Traduce una dirección virtual a offset de archivo usando los program headers (PT_LOAD)."""
    if elf[:4] != b"\x7fELF" or elf[4] != 2:
        raise ValueError("No es un ELF de 64 bits")
    e_phoff = struct.unpack_from("<Q", elf, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", elf, 0x36)
    for n in range(e_phnum):
        off = e_phoff + n * e_phentsize
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<IIQQQQ", elf, off)
        if p_type == 1 and p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:  # PT_LOAD
            start = p_offset + (vaddr - p_vaddr)
            return elf[start:start + size]
    raise ValueError(f"0x{vaddr:x} no está en ningún segmento PT_LOAD")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "binaries/crackme_level2"
    elf = open(path, "rb").read()
    k = read_vaddr(elf, K_VADDR, K_LEN)
    expected = read_vaddr(elf, EXP_VADDR, EXP_LEN)

    print(f"[+] Binario      : {path}")
    print(f"[+] K (4 bytes)  : {k.hex(' ')}")
    print(f"[+] EXPECTED (17): {expected.hex(' ')}")
    print()
    print(" i | EXPECTED | K[i%4] | EXPECTED^K = char")
    print("---+----------+--------+------------------")
    key = bytearray()
    for i, e in enumerate(expected):
        c = e ^ k[i % 4]
        key.append(c)
        print(f"{i:2d} |   0x{e:02x}   |  0x{k[i % 4]:02x}  |  0x{c:02x} '{chr(c)}'")

    # Verificación: aplicar la transformación hacia adelante debe reproducir EXPECTED
    assert bytes(c ^ k[i % 4] for i, c in enumerate(key)) == expected
    print()
    print(f"[+] Licencia reconstruida: {key.decode()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
