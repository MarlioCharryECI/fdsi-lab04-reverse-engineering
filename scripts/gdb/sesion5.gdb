set pagination off
set disassembly-flavor intel
set confirm off
echo \n### SESION 5 (Boss): binario stripped, sin nombres\n
info functions validate
break *0x401156
run FDSI-REVERSE-2026
echo \n--- primeras instrucciones de FUN_00401156 (sin simbolo) ---\n
x/12i $pc
x/s $rdi
delete
finish
info registers eax
continue
quit
