// Programa: crackme_level1 | Ghidra 11.3.2
// ===== Strings definidas y sus referencias (XREFs) =====
// 00400394  "/lib64/ld-linux-x86-64.so.2"  <- 00400088(?) _elfSectionHeaders::000000d0(?) 
// 00400479  "puts"  <- 
// 0040047e  "putchar"  <- 
// 00400486  "__libc_start_main"  <- 
// 00400498  "printf"  <- 
// 0040049f  "strcmp"  <- 
// 004004a6  "libc.so.6"  <- 
// 004004b0  "GLIBC_2.34"  <- 
// 004004bb  "GLIBC_2.2.5"  <- 
// 004004c7  "__gmon_start__"  <- 
// 00402004  "REDTEAM-101"  <- 004011e7(main) 004011ee(main) 0040123b(main) 00401237(main) 
// 00402010  "=== FDSI CrackMe Level 1 ==="  <- 004011f2(main) 004011f9(main) 
// 0040202d  "Uso: %s <password>\n"  <- 00401211(main) 00401218(main) 
// 00402041  "Access granted."  <- 0040124a(main) 00401251(main) 
// 00402051  "Access denied."  <- 00401265(main) 0040126c(main) 
// .comment::00000000  "GCC: (Debian 14.2.0-19) 14.2.0"  <- _elfSectionHeaders::00000690(?) 
// .debug_line_str::00000000  "/mnt/data/reverse_fsi_lab/crackme_level1.c"  <- _elfSectionHeaders::00000810(?) 
// .debug_str::00000000  "password"  <- _elfSectionHeaders::000007d0(?) 
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
// .strtab::000000a6  "crackme_level1.c"  <- 
// .strtab::000000b7  "print_flag"  <- 
// .strtab::000000c2  "__FRAME_END__"  <- 
// .strtab::000000d0  "_DYNAMIC"  <- 
// .strtab::000000d9  "__GNU_EH_FRAME_HDR"  <- 
// .strtab::000000ec  "_GLOBAL_OFFSET_TABLE_"  <- 
// .strtab::00000102  "putchar@GLIBC_2.2.5"  <- 
// .strtab::00000116  "__libc_start_main@GLIBC_2.34"  <- 
// .strtab::00000133  "puts@GLIBC_2.2.5"  <- 
// .strtab::00000144  "_edata"  <- 
// .strtab::0000014b  "_fini"  <- 
// .strtab::00000151  "printf@GLIBC_2.2.5"  <- 
// .strtab::00000164  "__data_start"  <- 
// .strtab::00000171  "strcmp@GLIBC_2.2.5"  <- 
// .strtab::00000184  "__gmon_start__"  <- 
// .strtab::00000193  "__dso_handle"  <- 
// .strtab::000001a0  "_IO_stdin_used"  <- 
// .strtab::000001af  "_end"  <- 
// .strtab::000001b4  "_dl_relocate_static_pie"  <- 
// .strtab::000001cc  "__bss_start"  <- 
// .strtab::000001d8  "main"  <- 
// .strtab::000001dd  "__TMC_END__"  <- 
// .strtab::000001e9  "_init"  <- 

// ===== FUN_00401020 @ 00401020 =====

void FUN_00401020(void)

{
  (*(code *)PTR_00403ff8)();
  return;
}



// ===== print_flag @ 00401156 =====

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void print_flag(void)

{
  uchar enc [26];
  uchar key;
  size_t i;
  
  builtin_memcpy(enc,"\x1c\x16\x1b\x1d!).(34=)\x05;(?\x05?,3>?49?\'",0x1a);
  for (i = 0; i < 0x1a; i = i + 1) {
    putchar((uint)(enc[i] ^ 0x5a));
  }
  putchar(10);
  return;
}



// ===== main @ 004011d8 =====

int main(int argc,char **argv)

{
  int iVar1;
  char **argv_local;
  int argc_local;
  char *password;
  
  puts("=== FDSI CrackMe Level 1 ===");
  if (argc == 2) {
    iVar1 = strcmp(argv[1],"REDTEAM-101");
    if (iVar1 == 0) {
      puts("Access granted.");
      print_flag();
      iVar1 = 0;
    }
    else {
      puts("Access denied.");
      iVar1 = 2;
    }
  }
  else {
    printf("Uso: %s <password>\n",*argv);
    iVar1 = 1;
  }
  return iVar1;
}


