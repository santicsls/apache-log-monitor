import tailer
import re
import sqlite3
import matplotlib.pyplot as plt
from datetime import datetime
from urllib.parse import urlsplit
import os

# Configuración inicial
LOG_FILE = '/var/log/apache2/access.log'
DB_FILE = 'access_logs.db'

# Patrón para parsear líneas de log de Apache
LOG_PATTERN = r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'

# Conexión a la base de datos SQLite
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()

# Crear tabla si no existe
c.execute('''
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    datetime TEXT,
    method TEXT,
    url TEXT,
    protocol TEXT,
    status TEXT,
    size TEXT,
    referer TEXT,
    user_agent TEXT,
    suspicious INTEGER DEFAULT 0
)
''')
conn.commit()

# Función para parsear una línea de log
def parse_log_line(line):
    match = re.match(LOG_PATTERN, line)
    if match:
        ip = match.group(1)
        datetime_str = match.group(2)
        request = match.group(3)
        status = match.group(4)
        size = match.group(5)
        referer = match.group(6)
        user_agent = match.group(7)
        
        # Separar el request en método, URL y protocolo
        request_parts = request.split()
        method = request_parts[0] if len(request_parts) >= 1 else None
        url = request_parts[1] if len(request_parts) >= 2 else None
        protocol = request_parts[2] if len(request_parts) == 3 else None
        
        return {
            'ip': ip,
            'datetime': datetime_str,
            'method': method,
            'url': url,
            'protocol': protocol,
            'status': status,
            'size': size,
            'referer': referer,
            'user_agent': user_agent
        }
    return None

# Función para detectar archivos sensibles
def is_sensitive_file(path):
    """Verifica si el camino de la URL apunta a un archivo o directorio sensible."""
    # Lista de extensiones y archivos sensibles
    sensitive_extensions = [
        # Archivos de Configuración
        r'\.env$', r'config\.(php|inc|json|xml|yml)$', r'settings\.(py|json)$', 
        r'database\.(yml|php|inc)$', r'web\.config$', r'\.ini$', r'\.conf$', 
        r'\.properties$', r'\.toml$',
        # Archivos de Autenticación
        r'\.htpasswd$', r'passwd$', r'shadow$', r'group$',
        # Archivos de Respaldo y Logs
        r'\.(bak|old)$', r'~$', r'\.log$', r'\.bash_history$', r'\.profile$', r'\.bashrc$',
        # Archivos de Código Fuente y Bases de Datos
        r'\.(php|asp|jsp|aspx)$', r'\.(sql|db|sqlite)$',
        # Archivos Específicos de Aplicaciones
        r'^wp-config\.php$', r'^configuration\.php$', r'^settings\.php$', 
        r'^application\.yml$', r'^credentials\.json$', r'^client_secrets\.json$', 
        r'^api_keys\.txt$', r'^ssh_keys$', r'^id_rsa$', r'^cert\.key$', 
        r'^apache2\.conf$', r'^httpd\.conf$', r'^nginx\.conf$', r'^php\.ini$'
    ]
    
    # Directorios sensibles
    sensitive_dirs = [
        r'admin\/?$', r'login\/?$', r'cgi-bin\/?$', r'backup\/?$', 
        r'scripts\/?$', r'etc\/?$', r'wp-admin\/?$', r'phpmyadmin\/?$'
    ]
    
    # Palabras clave en nombres de archivo
    sensitive_keywords = [
        r'secret', r'password', r'key', r'api', r'token', r'credential'
    ]
    
    # Si el path termina en '/', es un directorio
    if path.endswith('/'):
        for pattern in sensitive_dirs:
            if re.search(pattern, path, re.IGNORECASE):
                return True
    else:
        # Extraer el nombre del archivo del path
        filename = os.path.basename(path)
        # Revisar extensiones y archivos sensibles
        for pattern in sensitive_extensions:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        # Revisar palabras clave en el nombre del archivo
        for keyword in sensitive_keywords:
            if re.search(keyword, filename, re.IGNORECASE):
                return True
    return False

# Función para detectar inyección SQL
def has_sql_injection(query):
    """Verifica si la cadena de consulta contiene patrones de inyección SQL."""
    sql_patterns = [
        # Patrones comunes de inyección SQL
        r'\bOR\s+\d+=\d+\b', r'\bAND\s+\d+=\d+\b', r'\bUNION\s+(ALL\s+)?SELECT\b',
        r'\bSELECT\s+.*\s+FROM\b', r'\bWHERE\s+\d+=\d+\b', r'\bORDER\s+BY\s+\d+--',
        r'\bDROP\s+(TABLE|DATABASE)\b', r'\bINSERT\s+INTO\b', r'\bUPDATE\s+.*\s+SET\b',
        r'\bDELETE\s+FROM\b', r'\bSLEEP\(\d+\)',
        # Caracteres especiales usados en inyección SQL
        r'[\'";]', r'--', r'\/\*!.*\*\/', r'@@'
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return True
    return False

# Función para determinar si una solicitud es sospechosa
def is_suspicious(log):
    """Determina si una solicitud es sospechosa revisando la URL."""
    # Separar la URL en path y query
    url_parts = urlsplit(log['url'])
    path = url_parts.path
    query = url_parts.query
    
    # Verificar si el path apunta a un archivo o directorio sensible
    if is_sensitive_file(path):
        return True
    
    # Verificar si la query contiene patrones de inyección SQL
    if query and has_sql_injection(query):
        return True
    
    return False

# Función para insertar un log en la base de datos
def insert_log(log):
    suspicious = 1 if is_suspicious(log) else 0
    c.execute('''
    INSERT INTO logs (ip, datetime, method, url, protocol, status, size, referer, user_agent, suspicious)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (log['ip'], log['datetime'], log['method'], log['url'], log['protocol'], 
          log['status'], log['size'], log['referer'], log['user_agent'], suspicious))
    conn.commit()

# Función para obtener las URLs más solicitadas
def get_top_urls(limit=10):
    c.execute('''
    SELECT url, COUNT(*) as count
    FROM logs
    GROUP BY url
    ORDER BY count DESC
    LIMIT ?
    ''', (limit,))
    return c.fetchall()

# Función para graficar las URLs más solicitadas
def plot_top_urls():
    top_urls = get_top_urls()
    urls = [item[0] for item in top_urls]
    counts = [item[1] for item in top_urls]
    
    plt.barh(urls, counts)
    plt.xlabel('Cantidad de Peticiones')
    plt.title('URLs Más Solicitadas')
    plt.tight_layout()
    plt.show()

# Función principal para procesar los logs en tiempo real
def process_logs():
    print(f"Monitoreando logs en tiempo real desde {LOG_FILE}...")
    for line in tailer.follow(open(LOG_FILE)):
        log = parse_log_line(line)
        if log:
            insert_log(log)
            if is_suspicious(log):
                print(f"¡Alerta! Petición sospechosa: {log['ip']} - {log['method']} {log['url']} - {log['status']}")
            else:
                print(f"Registrada petición: {log['ip']} - {log['method']} {log['url']} - {log['status']}")

# Ejecución del programa
if __name__ == "__main__":
    # Iniciar el monitoreo en tiempo real
    try:
        process_logs()
    except KeyboardInterrupt:
        print("\nDeteniendo el monitoreo...")
        conn.close()
    except Exception as e:
        print(f"Error: {e}")
        conn.close()