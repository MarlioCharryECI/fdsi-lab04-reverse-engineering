// Programa: crackme_level2_stripped | Ghidra 11.3.2
// ===== Strings definidas y sus referencias (XREFs) =====
// 00400394  "/lib64/ld-linux-x86-64.so.2"  <- 00400088(?) _elfSectionHeaders::000000d0(?) 
// 00400479  "puts"  <- 
// 0040047e  "putchar"  <- 
// 00400486  "strlen"  <- 
// 0040048d  "__libc_start_main"  <- 
// 0040049f  "printf"  <- 
// 004004a6  "libc.so.6"  <- 
// 004004b0  "GLIBC_2.34"  <- 
// 004004bb  "GLIBC_2.2.5"  <- 
// 004004c7  "__gmon_start__"  <- 
// 00402010  "=== FDSI CrackMe Level 2 ==="  <- 00401276(FUN_00401267) 0040127d(FUN_00401267) 
// 00402030  "Hint: static + dynamic analysis."  <- 00401285(FUN_00401267) 0040128c(FUN_00401267) 
// 00402051  "Uso: %s <license-key>\n"  <- 004012a4(FUN_00401267) 004012ab(FUN_00401267) 
// 00402068  "License accepted."  <- 004012d6(FUN_00401267) 004012dd(FUN_00401267) 
// 0040207a  "Invalid license."  <- 004012f1(FUN_00401267) 004012f8(FUN_00401267) 
// .comment::00000000  "GCC: (Debian 14.2.0-19) 14.2.0"  <- _elfSectionHeaders::00000690(?) 
// .shstrtab::00000001  ".shstrtab"  <- 
// .shstrtab::0000000b  ".note.gnu.property"  <- 
// .shstrtab::0000001e  ".note.gnu.build-id"  <- 
// .shstrtab::00000031  ".interp"  <- 
// .shstrtab::00000039  ".gnu.hash"  <- 
// .shstrtab::00000043  ".dynsym"  <- 
// .shstrtab::0000004b  ".dynstr"  <- 
// .shstrtab::00000053  ".gnu.version"  <- 
// .shstrtab::00000060  ".gnu.version_r"  <- 
// .shstrtab::0000006f  ".rela.dyn"  <- 
// .shstrtab::00000079  ".rela.plt"  <- 
// .shstrtab::00000083  ".init"  <- 
// .shstrtab::00000089  ".text"  <- 
// .shstrtab::0000008f  ".fini"  <- 
// .shstrtab::00000095  ".rodata"  <- 
// .shstrtab::0000009d  ".eh_frame_hdr"  <- 
// .shstrtab::000000ab  ".eh_frame"  <- 
// .shstrtab::000000b5  ".note.ABI-tag"  <- 
// .shstrtab::000000c3  ".init_array"  <- 
// .shstrtab::000000cf  ".fini_array"  <- 
// .shstrtab::000000db  ".dynamic"  <- 
// .shstrtab::000000e4  ".got"  <- 
// .shstrtab::000000e9  ".got.plt"  <- 
// .shstrtab::000000f2  ".data"  <- 
// .shstrtab::000000f8  ".bss"  <- 
// .shstrtab::000000fd  ".comment"  <- 

// ===== FUN_00401020 @ 00401020 =====

void FUN_00401020(void)

{
  (*(code *)PTR_00403ff8)();
  return;
}



// ===== entry @ 00401070 =====

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00403fd8)
            (FUN_00401267,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



// ===== FUN_004010a0 @ 004010a0 =====

void FUN_004010a0(void)

{
  return;
}



// ===== FUN_004010b0 @ 004010b0 =====

/* WARNING: Removing unreachable block (ram,0x004010bd) */
/* WARNING: Removing unreachable block (ram,0x004010c7) */

void FUN_004010b0(void)

{
  return;
}



// ===== FUN_004010e0 @ 004010e0 =====

/* WARNING: Removing unreachable block (ram,0x004010ff) */
/* WARNING: Removing unreachable block (ram,0x00401109) */

void FUN_004010e0(void)

{
  return;
}



// ===== FUN_00401156 @ 00401156 =====

bool FUN_00401156(char *param_1)

{
  byte bVar1;
  size_t sVar2;
  bool bVar3;
  ulong local_18;
  
  sVar2 = strlen(param_1);
  if (sVar2 == 0x11) {
    bVar1 = 0;
    for (local_18 = 0; local_18 < 0x11; local_18 = local_18 + 1) {
      bVar1 = bVar1 | (&DAT_00402090)[local_18] ^
                      (&DAT_0040208b)[(uint)local_18 & 3] ^ param_1[local_18];
    }
    bVar3 = bVar1 == 0;
  }
  else {
    bVar3 = false;
  }
  return bVar3;
}



// ===== FUN_004011f3 @ 004011f3 =====

void FUN_004011f3(void)

{
  byte local_28 [23];
  byte local_11;
  ulong local_10;
  
  local_28[0] = 0x71;
  local_28[1] = 0x7b;
  local_28[2] = 0x76;
  local_28[3] = 0x70;
  local_28[4] = 0x4c;
  local_28[5] = 0x50;
  local_28[6] = 0x5f;
  local_28[7] = 0x5e;
  local_28[8] = 0x53;
  local_28[9] = 0x45;
  local_28[10] = 0x56;
  local_28[0xb] = 0x68;
  local_28[0xc] = 0x47;
  local_28[0xd] = 0x5b;
  local_28[0xe] = 0x42;
  local_28[0xf] = 0x44;
  local_28[0x10] = 0x68;
  local_28[0x11] = 0x50;
  local_28[0x12] = 0x53;
  local_28[0x13] = 0x55;
  local_28[0x14] = 0x4a;
  local_11 = 0x37;
  for (local_10 = 0; local_10 < 0x15; local_10 = local_10 + 1) {
    putchar((uint)(local_28[local_10] ^ local_11));
  }
  putchar(10);
  return;
}



// ===== FUN_00401267 @ 00401267 =====

undefined8 FUN_00401267(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  puts("=== FDSI CrackMe Level 2 ===");
  puts("Hint: static + dynamic analysis.");
  if (param_1 == 2) {
    iVar1 = FUN_00401156(param_2[1]);
    if (iVar1 == 0) {
      puts("Invalid license.");
      uVar2 = 3;
    }
    else {
      puts("License accepted.");
      FUN_004011f3();
      uVar2 = 0;
    }
  }
  else {
    printf("Uso: %s <license-key>\n",*param_2);
    uVar2 = 1;
  }
  return uVar2;
}


