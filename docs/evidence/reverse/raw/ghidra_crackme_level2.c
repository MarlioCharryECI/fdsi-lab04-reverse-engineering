// Programa: crackme_level2 | Ghidra 11.3.2
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
// 00402010  "=== FDSI CrackMe Level 2 ==="  <- 00401276(main) 0040127d(main) 
// 00402030  "Hint: static + dynamic analysis."  <- 00401285(main) 0040128c(main) 
// 00402051  "Uso: %s <license-key>\n"  <- 004012a4(main) 004012ab(main) 
// 00402068  "License accepted."  <- 004012d6(main) 004012dd(main) 
// 0040207a  "Invalid license."  <- 004012f1(main) 004012f8(main) 
// 0040208b  "#Qj"  <- 004011ae(validate_key) 004011b5(validate_key) 
// 00402090  "eD#R<fD/c'X"  <- 004011be(validate_key) 004011cc(validate_key) 
// .comment::00000000  "GCC: (Debian 14.2.0-19) 14.2.0"  <- _elfSectionHeaders::00000690(?) 
// .debug_line_str::00000000  "/mnt/data/reverse_fsi_lab/crackme_level2.c"  <- _elfSectionHeaders::00000810(?) 
// .debug_str::00000000  "putchar"  <- _elfSectionHeaders::000007d0(?) 
// .shstrtab::00000001  ".symtab"  <- 
// .shstrtab::00000009  ".strtab"  <- 
// .shstrtab::00000011  ".shstrtab"  <- 
// .shstrtab::0000001b  ".note.gnu.property"  <- 
// .shstrtab::0000002e  ".note.gnu.build-id"  <- 
// .shstrtab::00000041  ".interp"  <- 
// .shstrtab::00000049  ".gnu.hash"  <- 
// .shstrtab::00000053  ".dynsym"  <- 
// .shstrtab::0000005b  ".dynstr"  <- 
// .shstrtab::00000063  ".gnu.version"  <- 
// .shstrtab::00000070  ".gnu.version_r"  <- 
// .shstrtab::0000007f  ".rela.dyn"  <- 
// .shstrtab::00000089  ".rela.plt"  <- 
// .shstrtab::00000093  ".init"  <- 
// .shstrtab::00000099  ".text"  <- 
// .shstrtab::0000009f  ".fini"  <- 
// .shstrtab::000000a5  ".rodata"  <- 
// .shstrtab::000000ad  ".eh_frame_hdr"  <- 
// .shstrtab::000000bb  ".eh_frame"  <- 
// .shstrtab::000000c5  ".note.ABI-tag"  <- 
// .shstrtab::000000d3  ".init_array"  <- 
// .shstrtab::000000df  ".fini_array"  <- 
// .shstrtab::000000eb  ".dynamic"  <- 
// .shstrtab::000000f4  ".got"  <- 
// .shstrtab::000000f9  ".got.plt"  <- 
// .shstrtab::00000102  ".data"  <- 
// .shstrtab::00000108  ".bss"  <- 
// .shstrtab::0000010d  ".comment"  <- 
// .shstrtab::00000116  ".debug_aranges"  <- 
// .shstrtab::00000125  ".debug_info"  <- 
// .shstrtab::00000131  ".debug_abbrev"  <- 
// .shstrtab::0000013f  ".debug_line"  <- 
// .shstrtab::0000014b  ".debug_str"  <- 
// .shstrtab::00000156  ".debug_line_str"  <- 
// .strtab::00000001  "crt1.o"  <- 
// .strtab::00000008  "__abi_tag"  <- 
// .strtab::00000012  "crtstuff.c"  <- 
// .strtab::0000001d  "deregister_tm_clones"  <- 
// .strtab::00000032  "__do_global_dtors_aux"  <- 
// .strtab::00000048  "completed.0"  <- 
// .strtab::00000054  "__do_global_dtors_aux_fini_array_entry"  <- 
// .strtab::0000007b  "frame_dummy"  <- 
// .strtab::00000087  "__frame_dummy_init_array_entry"  <- 
// .strtab::000000a6  "crackme_level2.c"  <- 
// .strtab::000000b7  "validate_key"  <- 
// .strtab::000000c8  "expected.0"  <- 
// .strtab::000000d3  "reveal_flag"  <- 
// .strtab::000000df  "__FRAME_END__"  <- 
// .strtab::000000ed  "_DYNAMIC"  <- 
// .strtab::000000f6  "__GNU_EH_FRAME_HDR"  <- 
// .strtab::00000109  "_GLOBAL_OFFSET_TABLE_"  <- 
// .strtab::0000011f  "putchar@GLIBC_2.2.5"  <- 
// .strtab::00000133  "__libc_start_main@GLIBC_2.34"  <- 
// .strtab::00000150  "puts@GLIBC_2.2.5"  <- 
// .strtab::00000161  "_edata"  <- 
// .strtab::00000168  "_fini"  <- 
// .strtab::0000016e  "strlen@GLIBC_2.2.5"  <- 
// .strtab::00000181  "printf@GLIBC_2.2.5"  <- 
// .strtab::00000194  "__data_start"  <- 
// .strtab::000001a1  "__gmon_start__"  <- 
// .strtab::000001b0  "__dso_handle"  <- 
// .strtab::000001bd  "_IO_stdin_used"  <- 
// .strtab::000001cc  "_end"  <- 
// .strtab::000001d1  "_dl_relocate_static_pie"  <- 
// .strtab::000001e9  "__bss_start"  <- 
// .strtab::000001f5  "main"  <- 
// .strtab::000001fa  "__TMC_END__"  <- 
// .strtab::00000206  "_init"  <- 

// ===== FUN_00401020 @ 00401020 =====

void FUN_00401020(void)

{
  (*(code *)PTR_00403ff8)();
  return;
}



// ===== validate_key @ 00401156 =====

int validate_key(char *candidate)

{
  uint uVar1;
  size_t sVar2;
  char *candidate_local;
  uchar transformed;
  size_t n;
  size_t i;
  uint score;
  
  sVar2 = strlen(candidate);
  if (sVar2 == 0x11) {
    score = 0;
    for (i = 0; i < 0x11; i = i + 1) {
      score = score | (byte)("e\x15D#\x0e\x03R<f\x03D/\x0ec\'X\x15"[i] ^
                            "#Q\x17j"[(uint)i & 3] ^ candidate[i]);
    }
    uVar1 = (uint)(score == 0);
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// ===== reveal_flag @ 004011f3 =====

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void reveal_flag(void)

{
  uchar data [21];
  uchar key;
  size_t i;
  
  builtin_memcpy(data,"q{vpLP_^SEVhG[BDhPSUJ",0x15);
  for (i = 0; i < 0x15; i = i + 1) {
    putchar((uint)(data[i] ^ 0x37));
  }
  putchar(10);
  return;
}



// ===== main @ 00401267 =====

int main(int argc,char **argv)

{
  int iVar1;
  char **argv_local;
  int argc_local;
  
  puts("=== FDSI CrackMe Level 2 ===");
  puts("Hint: static + dynamic analysis.");
  if (argc == 2) {
    iVar1 = validate_key(argv[1]);
    if (iVar1 == 0) {
      puts("Invalid license.");
      iVar1 = 3;
    }
    else {
      puts("License accepted.");
      reveal_flag();
      iVar1 = 0;
    }
  }
  else {
    printf("Uso: %s <license-key>\n",*argv);
    iVar1 = 1;
  }
  return iVar1;
}


