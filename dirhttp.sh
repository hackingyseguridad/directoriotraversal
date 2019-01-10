# 
# Ver URL http puerto 80 con curl
# https://linux.die.net/man/1/curl
# curl
# -vvv Mostrar detalle en el resultado
#
# Uso.: ./dirhttp.sh "http://192.168.1.252:80/../../../../../../../etc/passwd"
# 
#
#!/bin/bash
echo "Uso.: ./dirhttp.sh http://url"
curl --insecure --silent -vvv --compressed \
-H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0" \
-H "Accept: text/html, applicattion/xhtml+xml, application/xml;q=0.9,*/*;q=0.8" \
-H "Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3" \
-H "Accept-Encoding: gzip, deflate, br" \
-H "Connection: keep-alive" \
-H "Upgrade-Insecure-Requests: 1" \
"$1"
