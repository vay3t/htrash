# Hacking Trash 1.0

Testeador de WAF que realiza múltiples peticiones a un sitio WEB objetivo
lanzando payloads de ataques vía GET y POST, a demás, entrega resultados del
estado HTTP de cada solicitud para comprobar si el WAF responde con un bloqueo
de tipo estado 403 o no.

Ejemplo de uso:

```bash
$ ./htrash.py 
+ WAF fuzzing attack testing
URL        : https://example.com/
Param name : test
+ Loading dictionary ...
 -> HTTP/GET ...
    - Request URL     : https://example.com/?test=%3Ciframe++src%3Dj%26Tab%3B...
    - Response status : 200
    - Response length : 1256 bytes.
 -> HTTP/POST ...
    - Request URL     : https://example.com/
    - Response status : 200
    - Response length : 1256 bytes.
 -> HTTP/GET ...
    - Request URL     : https://example.com/?test=C%3A%2Fapache%2Flogs%2Ferro...
    - Response status : 200
    - Response length : 1256 bytes.
 -> HTTP/POST ...
    - Request URL     : https://example.com/
    - Response status : 200
    - Response length : 1256 bytes.
 -> HTTP/GET ...
    - Request URL     : https://example.com/?test=%2F%25uff0e%25uff0e%2F%25uf...
    - Response status : 200
    - Response length : 1256 bytes.
 -> HTTP/POST ...
    - Request URL     : https://example.com/
    - Response status : 200
    - Response length : 1256 bytes.
 -> HTTP/GET ...
    - Request URL     : https://example.com/?test=0x2e0x2e%2F0x2e0x2e%2F0x2e0...
```

A demás, como resultado, genera un log para poder observar las respuestas al
final del proceso.

El nombre del parámetro es el parámetro del valor enviado ya sea vía GET uri
o POST body.


## Diccionario

El diccionario cuenta con más de 7300 payloads, algunos obtenidos desde el
fuzzer de Burpsuite, Owaspzap y algunos repositorios entre otros.

El formato del diccionario es una línea por cada payload, este se encodeará en
formato uri y será enviado en la petición HTTP, por lo cual no hay problema de
no escapar los caracteres o utilizar caracteres especiales.