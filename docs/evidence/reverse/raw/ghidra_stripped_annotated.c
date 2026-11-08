// crackme_level2_stripped - decompilado DESPUES de renombrar (Ghidra 11.3.2)

// ===== entry @ 00401070 =====

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00403fd8)
            (main_recovered,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



// ===== main_recovered @ 00401267 =====

/* main recuperado: entry -> __libc_start_main(FUN_00401267). Referencias a 'Invalid license.' y
   'License accepted.' */

undefined8 main_recovered(int argc,undefined8 *argv)

{
  int ok;
  undefined8 exit_code;
  
  puts("=== FDSI CrackMe Level 2 ===");
  puts("Hint: static + dynamic analysis.");
  if (argc == 2) {
    ok = check_license((char *)argv[1]);
    if (ok == 0) {
      puts("Invalid license.");
      exit_code = 3;
    }
    else {
      puts("License accepted.");
      print_secret_flag();
      exit_code = 0;
    }
  }
  else {
    printf("Uso: %s <license-key>\n",*argv);
    exit_code = 1;
  }
  return exit_code;
}



// ===== check_license @ 00401156 =====

/* check_license: len==17 y para cada i: input[i]^XOR_KEY_4B[i%4] == EXPECTED_17B[i]
   Acumula diferencias con OR; retorna 1 solo si acumulador==0 (comparacion sin salida temprana) */

bool check_license(char *user_key)

{
  size_t key_len;
  bool is_valid;
  ulong i;
  byte diff_acc;
  
  key_len = strlen(user_key);
  if (key_len == 0x11) {
    diff_acc = 0;
    for (i = 0; i < 0x11; i = i + 1) {
      diff_acc = diff_acc | EXPECTED_17B[i] ^ XOR_KEY_4B[(uint)i & 3] ^ user_key[i];
    }
    is_valid = diff_acc == 0;
  }
  else {
    is_valid = false;
  }
  return is_valid;
}



// ===== print_secret_flag @ 004011f3 =====

/* print_secret_flag: 21 bytes XOR 0x37 -> putchar */

void print_secret_flag(void)

{
  byte enc_flag [23];
  byte flag_xor;
  ulong i;
  
  enc_flag[0] = 0x71;
  enc_flag[1] = 0x7b;
  enc_flag[2] = 0x76;
  enc_flag[3] = 0x70;
  enc_flag[4] = 0x4c;
  enc_flag[5] = 0x50;
  enc_flag[6] = 0x5f;
  enc_flag[7] = 0x5e;
  enc_flag[8] = 0x53;
  enc_flag[9] = 0x45;
  enc_flag[10] = 0x56;
  enc_flag[0xb] = 0x68;
  enc_flag[0xc] = 0x47;
  enc_flag[0xd] = 0x5b;
  enc_flag[0xe] = 0x42;
  enc_flag[0xf] = 0x44;
  enc_flag[0x10] = 0x68;
  enc_flag[0x11] = 0x50;
  enc_flag[0x12] = 0x53;
  enc_flag[0x13] = 0x55;
  enc_flag[0x14] = 0x4a;
  flag_xor = 0x37;
  for (i = 0; i < 0x15; i = i + 1) {
    putchar((uint)(enc_flag[i] ^ flag_xor));
  }
  putchar(10);
  return;
}


