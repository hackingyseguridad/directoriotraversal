# 
# Ver URL https SSL con curl
# https://linux.die.net/man/1/curl
# curl
# -k fuerza a SSL en modo inseguro
# -s --silent muestra en pantalla los datos solicitados
# -vvv Mostrar detalle en el resultado
#
# la url entre comillas ""
#
#!/bin/bash
echo "Uso.: ./urlssl.sh https://url"
curl -k -s -vvv $1