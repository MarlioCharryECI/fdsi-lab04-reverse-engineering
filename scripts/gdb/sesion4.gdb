set pagination off
set disassembly-flavor intel
set confirm off
echo \n### SESION 4 (extra): manipular el retorno con una clave invalida\n
break *0x4012d2
run clave-incorrecta
echo \n--- justo despues de call validate_key: eax original ---\n
x/2i $pc
info registers eax
set $eax = 1
echo \n--- eax forzado a 1 ---\n
info registers eax
continue
quit
