#!/bin/bash
# hackingyseguridad.com 2025
# el fichero diccionario.txt debe contener los paiload de Path traversal
# Pedir al usuario que introduzca la URL
read -p "Introduce la URL para probar Path Traversal: " url
# Función para probar Path Traversal en una URL dada
test_path_traversal() {
    while IFS= read -r payload; do
        # Construir la URL completa con el payload
        test_url="${url}/${payload}"
        # Enviar una solicitud GET a la URL
        response=$(curl -s -o /dev/null -w "%{http_code}" "$test_url")
        # Imprimir el código de estado y la URL
        echo "Status Code: $response " | grep "Status Code: 200" && echo " - URL: $test_url"
    done < pathtraversal.txt
}
# Ejecutar las pruebas de Path Traversal
test_path_traversal

