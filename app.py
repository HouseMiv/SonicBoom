from flask import Flask, render_template, request, jsonify, Response
import requests
import time
import socket
import ssl
import subprocess
import re
import sqlite3
from urllib.parse import urlparse

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('sonic_boom.db')
    cursor = conn.cursor()
    
    # Удаляем старую таблицу и создаем новую с полной схемой
    cursor.execute('DROP TABLE IF EXISTS analysis_history')
    
    # Основная таблица анализов с полной схемой
    cursor.execute('''
        CREATE TABLE analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            load_time REAL,
            dns_info TEXT,
            ssl_info TEXT,
            avg_ping TEXT,
            ping_result TEXT,
            page_size INTEGER,
            seo_score TEXT,
            seo_score_numeric INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_favorite BOOLEAN DEFAULT 0,
            tags TEXT,
            notes TEXT,
            domain TEXT,
            last_check_date DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    

    
    # Таблица для алертов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def get_load_time(url):
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10)
        end_time = time.time()
        return end_time - start_time, response.headers.get('content-length', 0)
    except requests.exceptions.RequestException as e:
        return None, 0

def get_dns_info(url):
    try:
        # Извлекаем домен из URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Не удалось получить DNS информацию"

def get_ssl_info(url):
    try:
        # Извлекаем домен из URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(3.0)
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        return ssl_info
    except Exception as e:
        return str(e)

def get_http_headers(url):
    """Get HTTP headers for security analysis"""
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        headers = response.headers
        security_info = {}
        
        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'X-Frame-Options': 'X-Frame-Options',
            'X-XSS-Protection': 'X-XSS-Protection',
            'Content-Security-Policy': 'CSP',
            'Referrer-Policy': 'Referrer-Policy'
        }
        
        for header, name in security_headers.items():
            if header in headers:
                security_info[name] = headers[header]
        
        return security_info
    except Exception as e:
        return {"error": str(e)}

def check_mobile_optimization(url):
    """Check mobile optimization indicators"""
    try:
        response = requests.get(url, timeout=10)
        content = response.text.lower()
        headers = response.headers
        
        mobile_score = 0
        mobile_details = []
        
        # Check for viewport meta tag
        if 'viewport' in content:
            mobile_score += 5
            mobile_details.append("viewport meta tag")
        
        # Check for responsive design indicators
        if 'media=' in content and 'max-width' in content:
            mobile_score += 3
            mobile_details.append("responsive CSS")
        
        # Check for mobile-friendly indicators
        if 'mobile' in content or 'touch' in content:
            mobile_score += 2
            mobile_details.append("mobile indicators")
        
        # Check content length (shorter content loads faster on mobile)
        if len(content) < 50000:  # Less than 50KB
            mobile_score += 2
            mobile_details.append("оптимальный размер контента")
        
        # Check for image optimization indicators
        if 'lazy' in content or 'loading=' in content:
            mobile_score += 3
            mobile_details.append("lazy loading")
        
        return mobile_score, mobile_details
        
    except Exception as e:
        return 0, ["ошибка проверки мобильной оптимизации"]

def ping_url(url):
    # Извлекаем домен из URL
    parsed_url = urlparse(url)
    safe_url = parsed_url.netloc or parsed_url.path.split('/')[0]
    
    # Убираем порт если есть
    if ':' in safe_url:
        safe_url = safe_url.split(':')[0]
    
    # Сначала пробуем ping
    ping_result = try_ping_command(safe_url)
    
    # Проверяем, что ping вернул числовое значение (успех)
    try:
        int(ping_result[0])
        return ping_result
    except (ValueError, TypeError):
        # Если ping не работает, используем HTTP-запросы для измерения задержки
        return measure_http_latency(url)

def try_ping_command(host):
    """Попытка выполнить ping команду"""
    import platform
    system = platform.system().lower()
    
    try:
        if system == "windows":
            # Windows ping - уменьшаем количество пакетов и таймаут
            process = subprocess.Popen(['ping', '-n', '2', '-w', '3000', host], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, 
                                     encoding='cp866',
                                     creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            # Linux/Mac ping - уменьшаем количество пакетов и таймаут
            process = subprocess.Popen(['ping', '-c', '2', '-W', '3', host], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     encoding='utf-8')
        
        stdout, stderr = process.communicate(timeout=8)
        
        if process.returncode == 0:
            # Парсим результат в зависимости от ОС
            if system == "windows":
                # Windows: различные форматы вывода
                patterns = [
                    r'Среднее = (\d+)мс',
                    r'Average = (\d+)ms',
                    r'Average = (\d+)мс',
                    r'Среднее = (\d+)ms',
                    # Альтернативные форматы
                    r'время=(\d+)мс',
                    r'time=(\d+)ms',
                    # Ищем последние 4 значения времени и берем среднее
                    r'время=(\d+)мс.*время=(\d+)мс.*время=(\d+)мс.*время=(\d+)мс',
                    r'time=(\d+)ms.*time=(\d+)ms.*time=(\d+)ms.*time=(\d+)ms'
                ]
            else:
                # Linux/Mac: "avg = 45.123 ms"
                patterns = [
                    r'avg = (\d+\.?\d*) ms',
                    r'average = (\d+\.?\d*) ms'
                ]
            
            for pattern in patterns:
                match = re.search(pattern, stdout, re.IGNORECASE)
                if match:
                    if len(match.groups()) == 1:
                        # Одно значение времени
                        avg_ping = match.group(1)
                        try:
                            avg_ping = str(int(float(avg_ping)))
                        except:
                            pass
                        return avg_ping, f"Ping успешен: {avg_ping}ms\n{stdout}"
                    elif len(match.groups()) == 4:
                        # Четыре значения времени - вычисляем среднее
                        times = [int(match.group(i)) for i in range(1, 5)]
                        avg_ping = str(sum(times) // len(times))
                        return avg_ping, f"Ping успешен (среднее из 4): {avg_ping}ms\n{stdout}"
            
            # Если не нашли по шаблонам, попробуем извлечь все значения времени
            if system == "windows":
                time_matches = re.findall(r'время=(\d+)мс', stdout)
                if len(time_matches) >= 2:
                    times = [int(t) for t in time_matches]
                    avg_ping = str(sum(times) // len(times))
                    return avg_ping, f"Ping успешен (извлечено {len(times)} значений): {avg_ping}ms\n{stdout}"
            
            return "Не удалось определить среднее время пинга", f"Ping выполнен, но не удалось извлечь время:\n{stdout}"
        else:
            return "Ошибка при выполнении пинга", f"Ping завершился с ошибкой (код {process.returncode}):\n{stderr}"
            
    except subprocess.TimeoutExpired:
        if 'process' in locals():
            process.kill()
        return "Таймаут при выполнении пинга", "Превышено время ожидания (8с)"
    except Exception as e:
        return f"Ошибка при выполнении пинга: {str(e)}", f"Исключение: {str(e)}"

def measure_http_latency(url):
    """Измерение задержки через HTTP-запросы"""
    try:
        # Убеждаемся, что URL имеет протокол
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        total_time = 0
        successful_requests = 0
        results = []
        
        # Выполняем 2 быстрых HTTP-запроса для измерения задержки
        for i in range(2):
            try:
                start_time = time.time()
                # Используем GET вместо HEAD для большей совместимости
                response = requests.get(url, timeout=5, allow_redirects=True, stream=True)
                end_time = time.time()
                
                if response.status_code < 400:  # Успешный ответ
                    latency = (end_time - start_time) * 1000  # Конвертируем в миллисекунды
                    total_time += latency
                    successful_requests += 1
                    results.append(f"Запрос {i+1}: {latency:.0f}ms (статус: {response.status_code})")
                else:
                    results.append(f"Запрос {i+1}: HTTP {response.status_code}")
                
                # Закрываем соединение
                response.close()
                
            except requests.exceptions.Timeout:
                results.append(f"Запрос {i+1}: Таймаут (5с)")
            except requests.exceptions.ConnectionError as e:
                results.append(f"Запрос {i+1}: Ошибка соединения - {str(e)}")
            except requests.exceptions.RequestException as e:
                results.append(f"Запрос {i+1}: Ошибка запроса - {str(e)}")
            except Exception as e:
                results.append(f"Запрос {i+1}: Неожиданная ошибка - {str(e)}")
        
        if successful_requests > 0:
            avg_latency = total_time / successful_requests
            result_text = f"HTTP-задержка (GET запросы):\n" + "\n".join(results) + f"\n\nСредняя задержка: {avg_latency:.0f}ms"
            return str(int(avg_latency)), result_text
        else:
            error_details = "\n".join(results)
            return "Не удалось измерить HTTP-задержку", f"Все HTTP-запросы завершились с ошибкой:\n{error_details}"
            
    except Exception as e:
        return f"Ошибка при измерении HTTP-задержки: {str(e)}", str(e)

def calculate_seo_score_enhanced(load_time, avg_ping, dns_info, ssl_info, url, http_headers):
    score = 0
    details = []
    
    # Load time scoring (30 points max)
    if load_time < 0.5:
        score += 30
        details.append("🚀 Молниеносная скорость загрузки (< 0.5с)")
    elif load_time < 1:
        score += 25
        details.append("⚡ Отличная скорость загрузки (< 1с)")
    elif load_time < 2:
        score += 20
        details.append("✅ Хорошая скорость загрузки (< 2с)")
    elif load_time < 3:
        score += 15
        details.append("⚠️ Средняя скорость загрузки (< 3с)")
    elif load_time < 5:
        score += 10
        details.append("🐌 Медленная скорость загрузки (< 5с)")
    else:
        details.append("❌ Критически медленная загрузка (> 5с)")
    
    # Ping scoring (20 points max)
    if (avg_ping != "Не удалось определить среднее время пинга" and 
        avg_ping != "Ошибка при выполнении пинга" and
        avg_ping != "Не удалось измерить HTTP-задержку" and
        avg_ping != "Таймаут при выполнении пинга" and
        not avg_ping.startswith("Ошибка при измерении")):
        try:
            ping_num = int(avg_ping)
            if ping_num < 20:
                score += 20
                details.append("🎯 Идеальная сетевая задержка (< 20ms)")
            elif ping_num < 50:
                score += 18
                details.append("🏆 Отличная сетевая задержка (< 50ms)")
            elif ping_num < 100:
                score += 15
                details.append("✅ Хорошая сетевая задержка (< 100ms)")
            elif ping_num < 200:
                score += 12
                details.append("⚠️ Средняя сетевая задержка (< 200ms)")
            elif ping_num < 500:
                score += 8
                details.append("🐌 Высокая сетевая задержка (< 500ms)")
            else:
                details.append("❌ Критически высокая задержка (> 500ms)")
        except:
            details.append("❌ Не удалось измерить сетевую задержку")
    else:
        details.append("❌ Не удалось измерить сетевую задержку")
    
    # DNS scoring (10 points max)
    if dns_info != "Не удалось получить DNS информацию":
        score += 10
        details.append("🌐 DNS резолвинг работает корректно")
    else:
        details.append("❌ Проблемы с DNS резолвингом")
    
    # SSL scoring (10 points max)
    if "error" not in str(ssl_info).lower() and "exception" not in str(ssl_info).lower():
        score += 10
        details.append("🔒 SSL сертификат валиден")
    else:
        details.append("❌ Проблемы с SSL сертификатом")
    
    # Mobile optimization check (15 points max)
    mobile_score, mobile_details = check_mobile_optimization(url)
    
    # Combine mobile score with load time factor
    if load_time < 2:
        mobile_score += 5
    elif load_time < 3:
        mobile_score += 3
    elif load_time < 5:
        mobile_score += 1
    
    # Cap at 15 points max
    mobile_score = min(mobile_score, 15)
    score += mobile_score
    
    if mobile_score >= 12:
        details.append(f"📱 Отличная мобильная оптимизация ({', '.join(mobile_details)})")
    elif mobile_score >= 8:
        details.append(f"📱 Хорошая мобильная оптимизация ({', '.join(mobile_details)})")
    elif mobile_score >= 4:
        details.append(f"📱 Базовая мобильная оптимизация ({', '.join(mobile_details)})")
    else:
        details.append("📱 Требуется улучшение мобильной оптимизации")
    
    # URL structure check (5 points max)
    # Real URL structure analysis
    url_clean = True
    url_issues = []
    
    if "?" in url:
        url_clean = False
        url_issues.append("содержит параметры запроса")
    if "#" in url:
        url_clean = False
        url_issues.append("содержит якоря")
    if len(url.split("/")) > 4:  # Too many path segments
        url_clean = False
        url_issues.append("слишком глубокая структура")
    if url.count("//") > 1:  # Multiple protocols
        url_clean = False
        url_issues.append("неправильный формат")
    
    if url_clean:
        score += 5
        details.append("🔗 Чистая структура URL")
    else:
        details.append(f"🔗 Рекомендуется улучшить структуру URL: {', '.join(url_issues)}")
    
    # Security headers check (10 points max)
    security_score = 0
    security_details = []
    
    if isinstance(http_headers, dict) and "error" not in http_headers:
        if "HSTS" in http_headers:
            security_score += 3
            security_details.append("HSTS")
        if "X-Content-Type-Options" in http_headers:
            security_score += 2
            security_details.append("X-Content-Type-Options")
        if "X-Frame-Options" in http_headers:
            security_score += 2
            security_details.append("X-Frame-Options")
        if "X-XSS-Protection" in http_headers:
            security_score += 1
            security_details.append("X-XSS-Protection")
        if "CSP" in http_headers:
            security_score += 2
            security_details.append("CSP")
    
    score += security_score
    
    if security_score >= 8:
        details.append("🛡️ Отличная безопасность (все заголовки)")
    elif security_score >= 5:
        details.append(f"🛡️ Хорошая безопасность ({', '.join(security_details)})")
    elif security_score >= 2:
        details.append(f"🛡️ Базовая безопасность ({', '.join(security_details)})")
    else:
        details.append("🛡️ Требуется улучшение безопасности")
    
    # Convert to letter grade with detailed feedback
    if score >= 95:
        grade = "S+"
        feedback = "🌟 ИДЕАЛЬНЫЙ РЕЗУЛЬТАТ! Сайт работает на максимальной скорости!"
    elif score >= 90:
        grade = "S"
        feedback = "🏆 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Сайт демонстрирует превосходную производительность!"
    elif score >= 85:
        grade = "A+"
        feedback = "⭐ ВЕЛИКОЛЕПНЫЙ РЕЗУЛЬТАТ! Сайт работает очень быстро!"
    elif score >= 80:
        grade = "A"
        feedback = "✅ ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Сайт показывает высокую производительность!"
    elif score >= 75:
        grade = "A-"
        feedback = "👍 ХОРОШИЙ РЕЗУЛЬТАТ! Сайт работает хорошо!"
    elif score >= 70:
        grade = "B+"
        feedback = "✅ ХОРОШИЙ РЕЗУЛЬТАТ! Есть небольшие возможности для улучшения!"
    elif score >= 65:
        grade = "B"
        feedback = "⚠️ СРЕДНИЙ РЕЗУЛЬТАТ! Рекомендуется оптимизация!"
    elif score >= 60:
        grade = "B-"
        feedback = "⚠️ СРЕДНИЙ РЕЗУЛЬТАТ! Требуется улучшение производительности!"
    elif score >= 55:
        grade = "C+"
        feedback = "🐌 НИЗКИЙ РЕЗУЛЬТАТ! Необходима серьезная оптимизация!"
    elif score >= 50:
        grade = "C"
        feedback = "🐌 НИЗКИЙ РЕЗУЛЬТАТ! Критически необходима оптимизация!"
    elif score >= 40:
        grade = "D"
        feedback = "❌ ПЛОХОЙ РЕЗУЛЬТАТ! Сайт требует полной переработки!"
    else:
        grade = "F"
        feedback = "💀 КАТАСТРОФИЧЕСКИЙ РЕЗУЛЬТАТ! Сайт практически не работает!"
    
    return grade, feedback, details, score

def save_analysis(url, load_time, dns_info, ssl_info, avg_ping, ping_result, page_size, seo_score):
    conn = sqlite3.connect('sonic_boom.db')
    cursor = conn.cursor()
    
    # Извлекаем домен из URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    
    # Конвертируем SEO рейтинг в числовое значение
    seo_score_numeric = convert_seo_to_numeric(seo_score)
    
    cursor.execute('''
        INSERT INTO analysis_history 
        (url, load_time, dns_info, ssl_info, avg_ping, ping_result, page_size, seo_score, seo_score_numeric, domain, last_check_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (url, load_time, dns_info, str(ssl_info), avg_ping, ping_result, page_size, seo_score, seo_score_numeric, domain))
    
    # Проверяем на ухудшение показателей
    check_for_degradation(url, seo_score_numeric, load_time)
    
    conn.commit()
    conn.close()

def convert_seo_to_numeric(seo_score):
    """Конвертирует буквенный SEO рейтинг в числовое значение"""
    score_map = {
        'S+': 100, 'S': 95, 'A+': 90, 'A': 85, 'A-': 80,
        'B+': 75, 'B': 70, 'B-': 65, 'C+': 60, 'C': 55,
        'C-': 50, 'D+': 45, 'D': 40, 'D-': 35, 'F': 30
    }
    return score_map.get(seo_score, 0)

def check_for_degradation(url, current_score, current_load_time):
    """Проверяет ухудшение показателей и создает алерты"""
    conn = sqlite3.connect('sonic_boom.db')
    cursor = conn.cursor()
    
    # Получаем предыдущий анализ
    cursor.execute('''
        SELECT seo_score_numeric, load_time FROM analysis_history 
        WHERE url = ? AND id != (SELECT MAX(id) FROM analysis_history WHERE url = ?)
        ORDER BY timestamp DESC LIMIT 1
    ''', (url, url))
    
    result = cursor.fetchone()
    if result:
        prev_score, prev_load_time = result
        
        # Проверяем ухудшение SEO рейтинга
        if current_score < prev_score - 10:  # Ухудшение более чем на 10 баллов
            cursor.execute('''
                INSERT INTO alerts (url, alert_type, message)
                VALUES (?, 'seo_degradation', ?)
            ''', (url, f'SEO рейтинг ухудшился с {prev_score} до {current_score}'))
        
        # Проверяем ухудшение времени загрузки
        if current_load_time and prev_load_time and current_load_time > prev_load_time * 1.5:
            cursor.execute('''
                INSERT INTO alerts (url, alert_type, message)
                VALUES (?, 'performance_degradation', ?)
            ''', (url, f'Время загрузки увеличилось с {prev_load_time:.3f}s до {current_load_time:.3f}s'))
    
    conn.commit()
    conn.close()

def get_analysis_history(limit=10):
    conn = sqlite3.connect('sonic_boom.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM analysis_history 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    results = cursor.fetchall()
    conn.close()
    
    # Convert to list of dictionaries with all new fields
    columns = ['id', 'url', 'load_time', 'dns_info', 'ssl_info', 'avg_ping', 'ping_result', 'page_size', 'seo_score', 'seo_score_numeric', 'timestamp', 'is_favorite', 'tags', 'notes', 'domain', 'last_check_date']
    
    # Handle cases where old records might not have all columns
    history = []
    for row in results:
        record = {}
        for i, column in enumerate(columns):
            if i < len(row):
                record[column] = row[i]
            else:
                # Default values for missing columns
                if column == 'is_favorite':
                    record[column] = False
                elif column in ['tags', 'notes', 'domain']:
                    record[column] = None
                elif column == 'seo_score_numeric':
                    record[column] = convert_seo_to_numeric(record.get('seo_score', 'F'))
                else:
                    record[column] = None
        history.append(record)
    
    return history

def clear_analysis_history():
    conn = sqlite3.connect('sonic_boom.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM analysis_history')
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted_count

def delete_analysis_by_id(analysis_id):
    conn = sqlite3.connect('sonic_boom.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM analysis_history WHERE id = ?', (analysis_id,))
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted_count

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        if is_valid_url(url):
            # Get analysis data
            load_time, page_size = get_load_time(url)
            if load_time is None:
                return render_template('index.html', error="Не удалось загрузить сайт")
            
            dns_info = get_dns_info(url)
            ssl_info = get_ssl_info(url)
            avg_ping, ping_result = ping_url(url)
            
            # Get HTTP headers for security analysis
            http_headers = get_http_headers(url)
            
            # Calculate SEO score with enhanced analysis
            seo_grade, seo_feedback, seo_details, seo_score_value = calculate_seo_score_enhanced(load_time, avg_ping, dns_info, ssl_info, url, http_headers)
            
            # Save to database
            save_analysis(url, load_time, dns_info, ssl_info, avg_ping, ping_result, page_size, seo_grade)
            
            return render_template('result.html', 
                                url=url, 
                                load_time=load_time, 
                                dns_info=dns_info, 
                                ssl_info=ssl_info, 
                                avg_ping=avg_ping, 
                                ping_result=ping_result,
                                page_size=page_size,
                                seo_grade=seo_grade,
                                seo_feedback=seo_feedback,
                                seo_details=seo_details,
                                seo_score_value=seo_score_value,
                                http_headers=http_headers)
        else:
            error = "Неверный URL"
            return render_template('index.html', error=error)
    return render_template('index.html')

# API Endpoints

@app.route('/api/history', methods=['GET'])
def api_history():
    limit = request.args.get('limit', 10, type=int)
    history = get_analysis_history(limit)
    return jsonify(history)

@app.route('/api/stats', methods=['GET'])
def api_stats():
    conn = sqlite3.connect('sonic_boom.db')
    cursor = conn.cursor()
    
    # Get total analyses
    cursor.execute('SELECT COUNT(*) FROM analysis_history')
    total_analyses = cursor.fetchone()[0]
    
    # Get average load time
    cursor.execute('SELECT AVG(load_time) FROM analysis_history WHERE load_time IS NOT NULL')
    avg_load_time = cursor.fetchone()[0] or 0
    
    # Get most analyzed URLs
    cursor.execute('''
        SELECT url, COUNT(*) as count 
        FROM analysis_history 
        GROUP BY url 
        ORDER BY count DESC 
        LIMIT 5
    ''')
    top_urls = [{'url': row[0], 'count': row[1]} for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({
        'total_analyses': total_analyses,
        'average_load_time': round(avg_load_time, 3),
        'top_urls': top_urls
    })

@app.route('/api/clear-history', methods=['DELETE'])
def api_clear_history():
    try:
        deleted_count = clear_analysis_history()
        return jsonify({
            'success': True,
            'message': f'Удалено {deleted_count} записей из истории',
            'deleted_count': deleted_count
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/delete-analysis/<int:analysis_id>', methods=['DELETE'])
def api_delete_analysis(analysis_id):
    try:
        deleted_count = delete_analysis_by_id(analysis_id)
        if deleted_count > 0:
            return jsonify({
                'success': True,
                'message': 'Запись успешно удалена',
                'deleted_count': deleted_count
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Запись не найдена'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500



# Новые API endpoints для расширенной функциональности

@app.route('/api/history/filter', methods=['GET'])
def api_filter_history():
    """Фильтрация истории анализов"""
    try:
        # Получаем параметры фильтрации
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        seo_score = request.args.get('seo_score')
        load_time_min = request.args.get('load_time_min', type=float)
        load_time_max = request.args.get('load_time_max', type=float)
        domain = request.args.get('domain')
        favorites_only = request.args.get('favorites_only', type=bool)
        tags = request.args.get('tags')
        
        conn = sqlite3.connect('sonic_boom.db')
        cursor = conn.cursor()
        
        # Базовый запрос
        query = '''
            SELECT * FROM analysis_history WHERE 1=1
        '''
        params = []
        
        # Добавляем фильтры
        if date_from:
            query += ' AND DATE(timestamp) >= ?'
            params.append(date_from)
        
        if date_to:
            query += ' AND DATE(timestamp) <= ?'
            params.append(date_to)
        
        if seo_score:
            query += ' AND seo_score = ?'
            params.append(seo_score)
        
        if load_time_min is not None:
            query += ' AND load_time >= ?'
            params.append(load_time_min)
        
        if load_time_max is not None:
            query += ' AND load_time <= ?'
            params.append(load_time_max)
        
        if domain:
            query += ' AND domain LIKE ?'
            params.append(f'%{domain}%')
        
        if favorites_only:
            query += ' AND is_favorite = 1'
        
        if tags:
            query += ' AND tags LIKE ?'
            params.append(f'%{tags}%')
        
        query += ' ORDER BY timestamp DESC'
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        # Конвертируем в список словарей
        columns = ['id', 'url', 'load_time', 'dns_info', 'ssl_info', 'avg_ping', 'ping_result', 'page_size', 'seo_score', 'seo_score_numeric', 'timestamp', 'is_favorite', 'tags', 'notes', 'domain', 'last_check_date']
        history = [dict(zip(columns, row)) for row in results]
        
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Расширенная аналитика"""
    try:
        conn = sqlite3.connect('sonic_boom.db')
        cursor = conn.cursor()
        
        # Распределение SEO рейтингов
        cursor.execute('''
            SELECT seo_score, COUNT(*) as count 
            FROM analysis_history 
            GROUP BY seo_score 
            ORDER BY seo_score_numeric DESC
        ''')
        seo_distribution = [{'score': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Топ доменов по количеству анализов
        cursor.execute('''
            SELECT domain, COUNT(*) as count, AVG(seo_score_numeric) as avg_score
            FROM analysis_history 
            WHERE domain IS NOT NULL
            GROUP BY domain 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_domains = [{'domain': row[0], 'count': row[1], 'avg_score': round(row[2], 1)} for row in cursor.fetchall()]
        
        # Тренд SEO рейтингов по времени
        cursor.execute('''
            SELECT DATE(timestamp) as date, AVG(seo_score_numeric) as avg_score
            FROM analysis_history 
            WHERE timestamp >= DATE('now', '-30 days')
            GROUP BY DATE(timestamp)
            ORDER BY date
        ''')
        seo_trend = [{'date': row[0], 'avg_score': round(row[1], 1)} for row in cursor.fetchall()]
        
        # Статистика по времени загрузки
        cursor.execute('''
            SELECT 
                COUNT(CASE WHEN load_time < 1 THEN 1 END) as fast,
                COUNT(CASE WHEN load_time >= 1 AND load_time < 3 THEN 1 END) as medium,
                COUNT(CASE WHEN load_time >= 3 THEN 1 END) as slow
            FROM analysis_history 
            WHERE load_time IS NOT NULL
        ''')
        load_time_stats = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            'seo_distribution': seo_distribution,
            'top_domains': top_domains,
            'seo_trend': seo_trend,
            'load_time_stats': {
                'fast': load_time_stats[0],
                'medium': load_time_stats[1],
                'slow': load_time_stats[2]
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/favorites', methods=['POST'])
def api_toggle_favorite():
    """Переключение избранного"""
    try:
        data = request.get_json()
        analysis_id = data.get('analysis_id')
        is_favorite = data.get('is_favorite', True)
        
        conn = sqlite3.connect('sonic_boom.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE analysis_history SET is_favorite = ? WHERE id = ?', (is_favorite, analysis_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'is_favorite': is_favorite})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/alerts', methods=['GET', 'POST'])
def api_alerts():
    """Управление алертами"""
    try:
        conn = sqlite3.connect('sonic_boom.db')
        cursor = conn.cursor()
        
        if request.method == 'GET':
            # Получить все алерты
            cursor.execute('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50')
            alerts = cursor.fetchall()
            columns = ['id', 'url', 'alert_type', 'message', 'is_read', 'created_at']
            return jsonify([dict(zip(columns, row)) for row in alerts])
        
        elif request.method == 'POST':
            # Отметить алерт как прочитанный
            data = request.get_json()
            alert_id = data.get('alert_id')
            cursor.execute('UPDATE alerts SET is_read = 1 WHERE id = ?', (alert_id,))
            conn.commit()
            
            return jsonify({'success': True})
        
        conn.close()
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<format>')
def api_export(format):
    """Экспорт данных в разных форматах"""
    try:
        conn = sqlite3.connect('sonic_boom.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM analysis_history ORDER BY timestamp DESC')
        results = cursor.fetchall()
        conn.close()
        
        columns = ['id', 'url', 'load_time', 'dns_info', 'ssl_info', 'avg_ping', 'ping_result', 'page_size', 'seo_score', 'seo_score_numeric', 'timestamp', 'is_favorite', 'tags', 'notes', 'domain', 'last_check_date']
        
        if format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(columns)
            writer.writerows(results)
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=analysis_history.csv'}
            )
        
        elif format == 'json':
            history = [dict(zip(columns, row)) for row in results]
            return jsonify(history)
        
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# History page
@app.route('/history')
def history():
    """Объединенная страница истории с расширенной функциональностью"""
    return render_template('history.html')



@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)