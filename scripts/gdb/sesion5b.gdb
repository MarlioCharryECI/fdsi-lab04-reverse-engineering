set pagination off
set disassembly-flavor intel
set confirm off
echo \n### SESION 5b (Boss): stripped con clave invalida de 17 bytes\n
info functions validate
break *0x401156
run AAAAAAAAAAAAAAAAA
echo \n--- primeras instrucciones de FUN_00401156 (sin simbolo) ---\n
x/12i $pc
x/s $rdi
delete
finish
info registers eax
continue
quit
