from flask import Flask, render_template, request
import requests
import time
import socket
import ssl
import subprocess
import re


app = Flask(__name__)

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
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    return end_time - start_time

def get_dns_info(url):
    try:
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.gaierror:
        return "Не удалось получить DNS информацию"

def get_ssl_info(url):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
    conn.settimeout(3.0)
    try:
        conn.connect((url, 443))
        ssl_info = conn.getpeercert()
        return ssl_info
    except Exception as e:
        return str(e)

def ping_url(url):
    safe_url = url.split("//")[-1].split("/")[0]
    process = subprocess.Popen(['ping', '-n', '4', safe_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='cp866')
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        # Найти строку со средним временем пинга
        match = re.search(r'Среднее = (\d+)мс', stdout)
        if match:
            avg_ping = match.group(1)
            return avg_ping, stdout
        else:
            return "Не удалось определить среднее время пинга", stdout
    else:
        return "Ошибка при выполнении пинга", stderr

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        if is_valid_url(url):
            load_time = get_load_time(url)
            dns_info = get_dns_info(url.split("//")[-1])
            ssl_info = get_ssl_info(url.split("//")[-1])
            avg_ping, ping_result = ping_url(url)
            return render_template('result.html', url=url, load_time=load_time, dns_info=dns_info, ssl_info=ssl_info, avg_ping=avg_ping, ping_result=ping_result)
        else:
            error = "Неверный URL"
            return render_template('index.html', error=error)
    return render_template('index.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
