#!/bin/bash

# Pedir al usuario que introduzca la URL
read -p "Introduce la URL para probar Path Traversal: " url

# Comprobar si el fichero xss.txt existe
if [[ ! -f xss.txt ]]; then
    echo "El fichero diccionario.txt no existe. Por favor, crea el fichero con los payloads de Path Traversal."
    exit 1
fi

# Función para probar Path Traversal en una URL dada
test_path_traversal() {
    while IFS= read -r payload; do
        # Construir la URL completa con el payload
        test_url="${url}/${payload}"
        # Enviar una solicitud GET a la URL
        response=$(curl -s -o /dev/null -w "%{http_code}" "$test_url")
        # Imprimir el código de estado y la URL
        echo "Status Code: $response - URL: $test_url"
    done < diccionario.txt
}

# Ejecutar las pruebas de Path Traversal
test_path_traversal
