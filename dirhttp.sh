# 
# Ver URL http puerto 80 con curl
# https://linux.die.net/man/1/curl
# curl
# -vvv Mostrar detalle en el resultado
#
# Uso.: ./dirhttp.sh "http://192.168.1.252:80/../../../../../../../etc/passwd"
# la url entre comillas ""
#
#!/bin/bash
echo "Uso.: ./dirhttp.sh http://url"
curl -vvv $1
