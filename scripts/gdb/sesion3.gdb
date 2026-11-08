set pagination off
set disassembly-flavor intel
set confirm off
echo \n### SESION 3: clave candidata FDSI-REVERSE-2026\n
break *0x4011b9
commands
silent
printf "i=%2d  input=0x%02x '%c'  k[i&3]=0x%02x  ->  transformado=0x%02x  expected=0x%02x\n", *(long*)($rbp-0x10), $ecx, $ecx, $eax, ($eax^$ecx)&0xff, *(unsigned char*)(0x402090+*(long*)($rbp-0x10))
continue
end
break *0x4011e7
run FDSI-REVERSE-2026
echo \n--- fin del bucle: acumulador score [rbp-0x4] ---\n
x/wx $rbp-0x4
delete
finish
echo \n--- valor de retorno de validate_key (eax) ---\n
info registers eax
continue
quit
