set pagination off
set disassembly-flavor intel
set confirm off
echo \n### SESION 1: clave falsa corta (AAAA)\n
break validate_key
run AAAA
echo \n--- disassemble validate_key ---\n
disassemble validate_key
echo \n--- info registers (al entrar) ---\n
info registers rip rdi rsp rbp
echo \n--- argumento recibido (rdi) ---\n
x/s $rdi
echo \n--- datos en .rodata usados por la funcion ---\n
x/4xb 0x40208b
x/17xb 0x402090
break *0x40117a
continue
echo \n--- en el cmp de longitud: rax = strlen(input) vs [rbp-0x18] ---\n
info registers rax
x/gx $rbp-0x18
finish
echo \n--- valor de retorno de validate_key (eax) ---\n
info registers eax
continue
quit
