#!/usr/bin/env python3
"""
decode_level1_flag.py: Evidencia complementaria del Nivel 1.

La FLAG del Nivel 1 NO aparece con `strings` porque print_flag() la guarda
cifrada como inmediatos de 64 bits (movabs) y la descifra con XOR 0x5a antes
de imprimirla con putchar(). Este script reproduce esa lógica a partir de los
valores leídos en el desensamblado (objdump, ver raw/level1_objdump.txt):

  movabs rax,0x282e29211d1b161c ; mov [rbp-0x30],rax
  movabs rdx,0x3f283b05293d3433 ; mov [rbp-0x28],rdx
  movabs rax,0x3f053f283b05293d ; mov [rbp-0x26],rax   (se solapa a propósito)
  movabs rdx,0x273f39343f3e332c ; mov [rbp-0x1e],rdx
  mov BYTE PTR [rbp-0x9],0x5a   ; clave XOR
  bucle i = 0..0x19 (26 bytes): putchar(buf[i] ^ 0x5a)
"""
import struct

buf = bytearray(0x30)
writes = [(0x30 - 0x30, 0x282E29211D1B161C),
          (0x30 - 0x28, 0x3F283B05293D3433),
          (0x30 - 0x26, 0x3F053F283B05293D),
          (0x30 - 0x1E, 0x273F39343F3E332C)]
for off, val in writes:
    buf[off:off + 8] = struct.pack("<Q", val)

flag = bytes(b ^ 0x5A for b in buf[:0x1A])
print(flag.decode())
