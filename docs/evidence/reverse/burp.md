# Módulo complementario: Burp Suite Community + PortSwigger Web Security Academy

El módulo es opcional (bono) y no afecta la puntuación del crackme. Esta entrega incluye el procedimiento y la comparación entre análisis web e ingeniería inversa. La práctica en Academy no tiene capturas en este repositorio.

**Alcance autorizado:** únicamente el laboratorio de Web Security Academy asignado por el docente. No se intercepta tráfico de ningún otro sitio.

## Recursos

- Burp, Getting started: <https://portswigger.net/burp/documentation/desktop/getting-started>
- Academy, Getting started y videos: <https://portswigger.net/web-security/getting-started>

## Procedimiento (20 a 30 min)

1. Iniciar Burp Suite Community con *Temporary project* y *Use Burp defaults*.
2. En **Proxy > Intercept**, abrir el navegador integrado (ya trae el certificado de Burp).
3. Iniciar sesión en Academy y abrir solo el laboratorio asignado.
4. Activar *Intercept is on* y hacer clic en un producto o enlace del laboratorio. La petición queda retenida en Burp.
5. Clic derecho, **Send to Repeater** (`Ctrl+R`), y luego *Forward* o *Intercept off*.
6. En **Repeater**, cambiar un parámetro inocuo (por ejemplo `productId=1` por `productId=2`) y enviar.
7. Comparar las dos respuestas: código de estado, longitud y contenido.

## Análisis web vs. reverse engineering

| Dimensión | Burp Suite (análisis web) | Ghidra / GDB (reverse engineering) |
|---|---|---|
| Objeto analizado | **Tráfico** HTTP/HTTPS entre cliente y servidor | **Binario** compilado (ELF): código máquina y datos |
| Capa | Aplicación / protocolo (mensajes) | Instrucciones de CPU, memoria y registros |
| Qué se ve | Peticiones, cabeceras, cookies, parámetros, respuestas | Funciones, flujo de control, constantes, algoritmos |
| Lógica del servidor | Caja negra: solo se infiere por cómo responde | Caja blanca: el algoritmo se lee y se reconstruye |
| Manipulación típica | Modificar y repetir peticiones (Repeater) | Cambiar registros o memoria, parchear saltos (GDB) |
| Pregunta que responde | ¿Cómo reacciona la aplicación a entradas que no esperaba? | ¿Qué hace exactamente este programa y cómo decide? |
| En este lab | No aplica a los crackmes: no generan tráfico de red | Herramienta principal para los tres niveles |

Las dos técnicas llevan a la misma conclusión: no se debe confiar en el cliente. En la web, cualquier parámetro que envía el navegador se puede cambiar con Repeater. En el crackme, cualquier decisión que toma el binario se puede cambiar con GDB (`set $eax = 1`). En ambos casos el control de seguridad tiene que estar en un componente que el atacante no controla.
