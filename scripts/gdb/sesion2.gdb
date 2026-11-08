set pagination off
set disassembly-flavor intel
set confirm off
echo \n### SESION 2: longitud correcta (17) pero contenido incorrecto\n
break *0x4011d5
run AAAAAAAAAAAAAAAAA
echo \n--- iteracion i=0: al=expected[0]^(input[0]^k[0]) -> se acumula con OR ---\n
info registers eax
x/gx $rbp-0x10
delete
break *0x4011e7
continue
echo \n--- fin del bucle: acumulador score [rbp-0x4] ---\n
x/wx $rbp-0x4
finish
info registers eax
continue
quit
