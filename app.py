from flask import Flask, render_template, request, jsonify, Response
import requests
import time
import socket
import ssl
import subprocess
import re
import sqlite3
import json
import logging
import hashlib
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from html.parser import HTMLParser
import threading
import os
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

APP_VERSION = os.getenv('APP_VERSION', '1.0.0-beta')
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
HTTP_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
DEFAULT_HTTP_HEADERS = {'User-Agent': 'SonicBoomBot/1.0'}
CACHE_TTL_SECONDS = int(os.getenv('CACHE_TTL_SECONDS', '300'))
CACHE_MAX_ENTRIES = int(os.getenv('CACHE_MAX_ENTRIES', '1000'))
_max_workers_env = os.getenv('MAX_PARALLEL_WORKERS')
MAX_PARALLEL_WORKERS = (
    int(_max_workers_env)
    if _max_workers_env
    else min(8, max(1, (os.cpu_count() or 1) * 2))
)
SECURITY_SCORE_MAX = 10
DB_PATH = os.getenv('DB_PATH', 'sonic_boom.db')
DB_TIMEOUT = int(os.getenv('DB_TIMEOUT', '30'))
FREE_DAILY_LIMIT = int(os.getenv('FREE_DAILY_LIMIT', '20'))
FREE_LIMIT_EXEMPT_IPS = {'127.0.0.1', '::1'}
LOG_DIR = Path(os.getenv('LOG_DIR', 'logs'))
ANALYSIS_LOG_PATH = LOG_DIR / 'analysis.log'
LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', str(10 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))
STATS_ADMIN_TOKEN = os.getenv('STATS_ADMIN_TOKEN', '')

_analysis_cache = {}
_cache_lock = threading.Lock()
_cache_stats = {'hits': 0, 'misses': 0, 'evictions': 0}
_metrics_lock = threading.Lock()
_runtime_metrics = {
    'analysis_count': 0,
    'success_count': 0,
    'error_count': 0,
    'total_duration_ms': 0,
}

logger = logging.getLogger('sonicboom')

def setup_logging():
    LOG_DIR.mkdir(exist_ok=True)
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return
    handler = RotatingFileHandler(
        ANALYSIS_LOG_PATH,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8',
    )
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)

setup_logging()

def mask_ip(ip):
    if not ip:
        return 'unknown'
    if ip in FREE_LIMIT_EXEMPT_IPS:
        return 'localhost'
    if ':' in ip:
        digest = hashlib.sha256(ip.encode()).hexdigest()[:8]
        return f'ipv6:{digest}'
    parts = ip.split('.')
    if len(parts) == 4:
        return f'{parts[0]}.{parts[1]}.{parts[2]}.xxx'
    digest = hashlib.sha256(ip.encode()).hexdigest()[:8]
    return f'ip:{digest}'

def admin_stats_allowed():
    """Full metrics: localhost or STATS_ADMIN_TOKEN (X-Admin-Token header / ?token=)."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        client_ip = forwarded.split(',')[0].strip()
    else:
        client_ip = request.remote_addr or '127.0.0.1'
    if client_ip in FREE_LIMIT_EXEMPT_IPS:
        return True
    if not STATS_ADMIN_TOKEN:
        return False
    token = request.headers.get('X-Admin-Token') or request.args.get('token', '')
    return token == STATS_ADMIN_TOKEN

_db_lock = threading.Lock()

def _configure_connection(conn):
    conn.execute(f'PRAGMA busy_timeout={DB_TIMEOUT * 1000}')

@contextmanager
def db_session(write=False):
    """Serialized SQLite access — one connection at a time within this process."""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
        _configure_connection(conn)
        try:
            yield conn
            if write:
                conn.commit()
        except Exception:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

def _merge_headers(extra=None):
    headers = DEFAULT_HTTP_HEADERS.copy()
    if extra:
        headers.update(extra)
    return headers

def http_get(url, **kwargs):
    kwargs.setdefault('timeout', HTTP_TIMEOUT)
    kwargs['headers'] = _merge_headers(kwargs.get('headers'))
    return requests.get(url, **kwargs)

def http_head(url, **kwargs):
    kwargs.setdefault('timeout', HTTP_TIMEOUT)
    kwargs['headers'] = _merge_headers(kwargs.get('headers'))
    return requests.head(url, **kwargs)

def _cache_evict_expired():
    now = time.time()
    expired = [k for k, v in _analysis_cache.items() if now - v['ts'] >= CACHE_TTL_SECONDS]
    for key in expired:
        del _analysis_cache[key]
        _cache_stats['evictions'] += 1

def _cache_get(key):
    with _cache_lock:
        entry = _analysis_cache.get(key)
        if not entry:
            _cache_stats['misses'] += 1
            return None
        if time.time() - entry['ts'] >= CACHE_TTL_SECONDS:
            del _analysis_cache[key]
            _cache_stats['evictions'] += 1
            _cache_stats['misses'] += 1
            return None
        _cache_stats['hits'] += 1
        return entry['value']

def _cache_set(key, value):
    with _cache_lock:
        _cache_evict_expired()
        if len(_analysis_cache) >= CACHE_MAX_ENTRIES and key not in _analysis_cache:
            oldest_key = min(_analysis_cache, key=lambda k: _analysis_cache[k]['ts'])
            del _analysis_cache[oldest_key]
            _cache_stats['evictions'] += 1
        _analysis_cache[key] = {'ts': time.time(), 'value': value}

def get_cache_stats():
    with _cache_lock:
        total = _cache_stats['hits'] + _cache_stats['misses']
        hit_rate = round(_cache_stats['hits'] / total * 100, 1) if total else 0.0
        return {
            'hits': _cache_stats['hits'],
            'misses': _cache_stats['misses'],
            'evictions': _cache_stats['evictions'],
            'entries': len(_analysis_cache),
            'hit_rate': hit_rate,
            'ttl_seconds': CACHE_TTL_SECONDS,
            'max_entries': CACHE_MAX_ENTRIES,
        }

def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def try_consume_daily_quota(ip, limit=FREE_DAILY_LIMIT):
    if ip in FREE_LIMIT_EXEMPT_IPS:
        return True, 0
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute('SELECT count FROM daily_usage WHERE ip = ? AND date = ?', (ip, today))
        row = cursor.fetchone()
        current = row[0] if row else 0
        if current >= limit:
            conn.rollback()
            return False, current
        if row:
            cursor.execute(
                'UPDATE daily_usage SET count = count + 1 WHERE ip = ? AND date = ?',
                (ip, today))
        else:
            cursor.execute(
                'INSERT INTO daily_usage (ip, date, count) VALUES (?, ?, 1)',
                (ip, today))
        conn.commit()
    return True, current + 1

def get_daily_usage(ip):
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT count FROM daily_usage WHERE ip = ? AND date = ?', (ip, today))
        row = cursor.fetchone()
    return row[0] if row else 0

def record_analysis(duration_ms, success=True):
    with _metrics_lock:
        _runtime_metrics['analysis_count'] += 1
        _runtime_metrics['total_duration_ms'] += duration_ms
        if success:
            _runtime_metrics['success_count'] += 1
        else:
            _runtime_metrics['error_count'] += 1

def get_runtime_metrics():
    with _metrics_lock:
        total = _runtime_metrics['analysis_count']
        errors = _runtime_metrics['error_count']
        avg_ms = round(_runtime_metrics['total_duration_ms'] / total) if total else 0
        error_rate = round(errors / total * 100, 1) if total else 0.0
        return {
            'analysis_count': total,
            'success_count': _runtime_metrics['success_count'],
            'error_count': errors,
            'avg_duration_ms': avg_ms,
            'error_rate': error_rate,
        }

def log_analysis_event(url, duration_ms, cache_hit, status, error=None, client_ip=None):
    event = {
        'ts': datetime.now(timezone.utc).isoformat(),
        'url': url,
        'duration_ms': duration_ms,
        'cache_hit': cache_hit,
        'status': status,
        'client_ip': mask_ip(client_ip),
    }
    if error:
        event['error'] = error
    logger.info(json.dumps(event, ensure_ascii=False))

def _cache_key(prefix, url):
    return f"{prefix}:{_extract_domain(url) or url}"

# Database setup
def _migrate_analysis_history(cursor):
    cursor.execute('PRAGMA table_info(analysis_history)')
    columns = {row[1] for row in cursor.fetchall()}
    for column, col_type in (
        ('ssl_days_remaining', 'INTEGER'),
        ('security_score', 'INTEGER'),
        ('audit_snapshot', 'TEXT'),
    ):
        if column not in columns:
            cursor.execute(f'ALTER TABLE analysis_history ADD COLUMN {column} {col_type}')

def init_db():
    with db_session(write=True) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
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
                last_check_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                ssl_days_remaining INTEGER,
                security_score INTEGER,
                audit_snapshot TEXT
            )
        ''')
        _migrate_analysis_history(cursor)

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

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_usage (
                ip TEXT NOT NULL,
                date TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                PRIMARY KEY (ip, date)
            )
        ''')

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

def _extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split('/')[0]

def _format_bytes(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B", size_bytes
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB", size_bytes
    return f"{size_bytes / (1024 * 1024):.1f} MB", size_bytes

def _parse_cert_date(date_str):
    normalized = ' '.join(date_str.split())
    formats = (
        '%b %d %H:%M:%S %Y GMT',
        '%b %d %H:%M:%S %Y %Z',
        '%Y%m%d%H%M%SZ',
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(normalized, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise ValueError(f'Неизвестный формат даты сертификата: {date_str}')

def _cert_field(cert, field):
    try:
        return dict(x[0] for x in cert.get(field, ()))
    except Exception:
        return {}

def _extract_san_domains(cert):
    try:
        return [value for key, value in cert.get('subjectAltName', ()) if key == 'DNS']
    except Exception:
        return []

def _ssl_is_valid(ssl_info):
    if isinstance(ssl_info, dict):
        return ssl_info.get('valid', False)
    return "error" not in str(ssl_info).lower() and "exception" not in str(ssl_info).lower()

class _PageHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ''
        self.in_title = False
        self.meta = {}
        self.canonical = None
        self.h1_texts = []
        self.h2_count = 0
        self._current_heading = None
        self._heading_buffer = []
        self.images_total = 0
        self.images_missing_alt = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): v for k, v in attrs}
        tag = tag.lower()
        if tag == 'title':
            self.in_title = True
        elif tag == 'meta':
            name = attrs_dict.get('name', '').lower()
            prop = attrs_dict.get('property', '').lower()
            content = attrs_dict.get('content', '')
            if name:
                self.meta[name] = content
            if prop:
                self.meta[prop] = content
        elif tag == 'link' and attrs_dict.get('rel', '').lower() == 'canonical':
            self.canonical = attrs_dict.get('href')
        elif tag in ('h1', 'h2'):
            self._current_heading = tag
            self._heading_buffer = []
        elif tag == 'img':
            self.images_total += 1
            alt = attrs_dict.get('alt')
            if alt is None or not str(alt).strip():
                self.images_missing_alt += 1

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == 'title':
            self.in_title = False
        elif tag == 'h1' and self._current_heading == 'h1':
            text = ''.join(self._heading_buffer).strip()
            if text:
                self.h1_texts.append(text)
            self._current_heading = None
        elif tag == 'h2' and self._current_heading == 'h2':
            self.h2_count += 1
            self._current_heading = None

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        elif self._current_heading:
            self._heading_buffer.append(data)

def _detect_http_to_https(chain):
    if len(chain) < 2:
        return False
    for i in range(len(chain) - 1):
        if chain[i].startswith('http://') and chain[i + 1].startswith('https://'):
            return True
    return chain[0].startswith('http://') and chain[-1].startswith('https://')

def analyze_redirects(url, max_hops=10):
    chain = [url]
    redirect_steps = []
    visited = {url}
    current = url
    try:
        # Новый Session на каждый анализ — безопасно для потоков
        with requests.Session() as session:
            session.headers.update(DEFAULT_HTTP_HEADERS)
            for _ in range(max_hops):
                response = session.get(current, allow_redirects=False, timeout=HTTP_TIMEOUT)
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location')
                    if not location:
                        break
                    next_url = urljoin(current, location)
                    redirect_steps.append({
                        'code': response.status_code,
                        'from': current,
                        'to': next_url,
                    })
                    if next_url in visited:
                        return {
                            'status_code': response.status_code,
                            'status_text': response.reason,
                            'final_url': current,
                            'redirect_count': len(chain) - 1,
                            'chain': chain,
                            'redirect_steps': redirect_steps,
                            'http_to_https': _detect_http_to_https(chain + [next_url]),
                            'has_cycle': True,
                            'chain_too_long': len(chain) - 1 > 3,
                            'error': None,
                        }
                    chain.append(next_url)
                    visited.add(next_url)
                    current = next_url
                else:
                    return {
                        'status_code': response.status_code,
                        'status_text': response.reason,
                        'final_url': current,
                        'redirect_count': len(chain) - 1,
                        'chain': chain,
                        'redirect_steps': redirect_steps,
                        'http_to_https': _detect_http_to_https(chain),
                        'has_cycle': False,
                        'chain_too_long': len(chain) - 1 > 3,
                        'error': None,
                    }
            return {
                'status_code': None,
                'status_text': 'Too Many Redirects',
                'final_url': current,
                'redirect_count': len(chain) - 1,
                'chain': chain,
                'redirect_steps': redirect_steps,
                'http_to_https': _detect_http_to_https(chain),
                'has_cycle': False,
                'chain_too_long': True,
                'error': 'Превышено максимальное число редиректов',
            }
    except requests.exceptions.RequestException as e:
        return {
            'status_code': None,
            'status_text': 'Error',
            'final_url': url,
            'redirect_count': 0,
            'chain': [url],
            'redirect_steps': [],
            'http_to_https': False,
            'has_cycle': False,
            'chain_too_long': False,
            'error': str(e),
        }

def fetch_page_content(url):
    try:
        start_time = time.time()
        response = http_get(url, allow_redirects=True)
        load_time = time.time() - start_time
        content = response.content
        size_bytes = len(content)
        encoding = response.apparent_encoding or 'utf-8'
        html = content.decode(encoding, errors='replace')
        content_encoding = response.headers.get('Content-Encoding', '').lower()
        compression_map = {'br': 'Brotli', 'gzip': 'Gzip', 'deflate': 'Deflate'}
        return {
            'load_time': load_time,
            'html': html,
            'size_bytes': size_bytes,
            'size_source': 'response.content',
            'compression': {
                'enabled': bool(content_encoding),
                'encoding': content_encoding or 'none',
                'display': compression_map.get(content_encoding, content_encoding.upper() if content_encoding else 'None'),
            },
            'status_code': response.status_code,
            'error': None,
        }
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def _meta_length_status(length, good_min, good_max):
    if length < good_min:
        return 'too_short'
    if length > good_max:
        return 'too_long'
    return 'good'

def _meta_length_hint(status):
    hints = {
        'too_short': 'Too short',
        'too_long': 'Too long',
        'good': 'Good',
        'missing': 'Missing',
    }
    return hints.get(status, '')

def analyze_meta_seo(html):
    parser = _PageHTMLParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    title = parser.title.strip()
    title_len = len(title)
    if not title:
        title_status = 'missing'
        title_hint = 'Missing'
    else:
        title_hint = _meta_length_hint(_meta_length_status(title_len, 30, 60))
        title_status = 'ok' if title_hint == 'Good' else 'warning'

    description = parser.meta.get('description', '').strip()
    desc_len = len(description)
    if not description:
        desc_status = 'missing'
        desc_hint = 'Missing'
    else:
        desc_hint = _meta_length_hint(_meta_length_status(desc_len, 70, 160))
        desc_status = 'ok' if desc_hint == 'Good' else 'warning'

    og_required = ['og:title', 'og:description', 'og:image', 'og:url']
    og_present = [t for t in og_required if t in parser.meta and parser.meta[t].strip()]
    og_count = len(og_present)
    og_total = len(og_required)
    if og_count == og_total:
        og_status = 'ok'
    elif og_count > 0:
        og_status = 'partial'
    else:
        og_status = 'missing'

    return {
        'title': {
            'present': bool(title), 'text': title, 'length': title_len,
            'status': title_status, 'hint': title_hint,
        },
        'description': {
            'present': bool(description), 'text': description, 'length': desc_len,
            'status': desc_status, 'hint': desc_hint,
        },
        'canonical': {'present': bool(parser.canonical), 'url': parser.canonical or ''},
        'robots_meta': {'present': 'robots' in parser.meta, 'content': parser.meta.get('robots', '')},
        'og': {
            'status': og_status,
            'required': og_required,
            'present': og_present,
            'score': f'{og_count}/{og_total}',
            'tags_count': og_count,
        },
    }

def _parse_robots_txt(content):
    blocks_indexing = False
    sitemap_urls = []
    in_wildcard_block = False

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        lower = line.lower()
        if lower.startswith('user-agent:'):
            agent = line.split(':', 1)[1].strip()
            in_wildcard_block = agent == '*'
        elif lower.startswith('sitemap:'):
            sitemap_urls.append(line.split(':', 1)[1].strip())
        elif lower.startswith('disallow:') and in_wildcard_block:
            path = line.split(':', 1)[1].strip()
            if path == '/':
                blocks_indexing = True

    if not blocks_indexing:
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if re.match(r'disallow:\s*/\s*$', line, re.IGNORECASE):
                blocks_indexing = True
                break

    if blocks_indexing:
        content_status = 'blocks_indexing'
    else:
        content_status = 'valid'

    return {
        'content_status': content_status,
        'blocks_indexing': blocks_indexing,
        'sitemap_urls': sitemap_urls,
    }

def _check_sitemap_url(sitemap_url):
    try:
        response = http_get(sitemap_url)
        ok = response.status_code == 200 and len(response.text.strip()) > 0
        return {
            'present': ok,
            'status_code': response.status_code,
            'url': sitemap_url,
        }
    except requests.exceptions.RequestException:
        return {'present': False, 'status_code': None, 'url': sitemap_url}

def check_robots_sitemap(url):
    cache_key = _cache_key('robots', url)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    robots_result = {
        'present': False,
        'status_code': None,
        'url': base + '/robots.txt',
        'content_status': 'missing',
        'blocks_indexing': False,
        'sitemap_urls': [],
    }
    try:
        response = http_get(robots_result['url'])
        robots_result['status_code'] = response.status_code
        if response.status_code == 200 and response.text.strip():
            robots_result['present'] = True
            parsed_robots = _parse_robots_txt(response.text)
            robots_result.update(parsed_robots)
    except requests.exceptions.RequestException:
        pass

    sitemap_candidates = [base + '/sitemap.xml', base + '/sitemap_index.xml']
    for sitemap_url in robots_result.get('sitemap_urls', []):
        if sitemap_url not in sitemap_candidates:
            sitemap_candidates.append(sitemap_url)

    sitemap_result = {
        'present': False,
        'status_code': None,
        'url': sitemap_candidates[0],
        'found_url': None,
        'urls_checked': sitemap_candidates,
    }
    for candidate in sitemap_candidates:
        checked = _check_sitemap_url(candidate)
        if checked['present']:
            sitemap_result.update(checked)
            sitemap_result['found_url'] = candidate
            break

    result = {'robots': robots_result, 'sitemap': sitemap_result}
    _cache_set(cache_key, result)
    return result

def analyze_headings(html):
    parser = _PageHTMLParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    h1_count = len(parser.h1_texts)
    if h1_count == 1:
        status = 'ok'
    elif h1_count == 0:
        status = 'missing'
    else:
        status = 'warning'
    return {
        'h1_count': h1_count,
        'h2_count': parser.h2_count,
        'h1_texts': parser.h1_texts[:5],
        'status': status,
    }

def analyze_images(html):
    parser = _PageHTMLParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return {
        'total': parser.images_total,
        'missing_alt': parser.images_missing_alt,
        'with_alt': parser.images_total - parser.images_missing_alt,
    }

def format_page_size_info(size_bytes):
    display, _ = _format_bytes(size_bytes)
    if size_bytes < 1024 * 1024:
        recommendation = 'Размер страницы в норме'
        status = 'ok'
    elif size_bytes < 2 * 1024 * 1024:
        recommendation = 'Рекомендуется уменьшить размер ниже 1 MB'
        status = 'warning'
    else:
        recommendation = 'Критически большой размер — требуется оптимизация'
        status = 'error'
    return {'size_bytes': size_bytes, 'display': display, 'recommendation': recommendation, 'status': status, 'source': 'response.content'}

def get_load_time(url):
    try:
        start_time = time.time()
        response = http_get(url)
        end_time = time.time()
        return end_time - start_time, response.headers.get('content-length', 0)
    except requests.exceptions.RequestException as e:
        return None, 0

def get_dns_info(url):
    cache_key = _cache_key('dns', url)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        domain = _extract_domain(url)
        ip_address = socket.gethostbyname(domain)
        _cache_set(cache_key, ip_address)
        return ip_address
    except socket.gaierror:
        result = "Не удалось получить DNS информацию"
        _cache_set(cache_key, result)
        return result

def get_ssl_info(url):
    cache_key = _cache_key('ssl', url)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    domain = _extract_domain(url)
    if ':' in domain:
        domain = domain.split(':')[0]
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5.0)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        issuer_data = _cert_field(cert, 'issuer')
        subject_data = _cert_field(cert, 'subject')
        issuer_name = issuer_data.get('organizationName') or issuer_data.get('commonName') or 'Unknown'
        subject_cn = subject_data.get('commonName') or domain
        san_domains = _extract_san_domains(cert)

        issued = expires = None
        days_remaining = None
        status = 'ok'
        try:
            not_before = _parse_cert_date(cert['notBefore'])
            not_after = _parse_cert_date(cert['notAfter'])
            issued = not_before.strftime('%d.%m.%Y')
            expires = not_after.strftime('%d.%m.%Y')
            days_remaining = (not_after - datetime.now(timezone.utc)).days
            if days_remaining < 0:
                status = 'expired'
            elif days_remaining <= 14:
                status = 'critical'
            elif days_remaining <= 30:
                status = 'warning'
        except Exception:
            status = 'unknown_dates'

        result = {
            'valid': True,
            'issuer': issuer_name,
            'subject': subject_cn,
            'san': san_domains[:10],
            'san_primary': san_domains[0] if san_domains else subject_cn,
            'issued': issued,
            'expires': expires,
            'days_remaining': days_remaining,
            'status': status,
            'error': None,
        }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        result = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'san': [],
            'san_primary': None,
            'issued': None,
            'expires': None,
            'days_remaining': None,
            'status': 'error',
            'error': str(e),
        }
        _cache_set(cache_key, result)
        return result

def get_http_headers(url):
    """Get HTTP headers for security analysis"""
    cache_key = _cache_key('headers', url)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        response = http_head(url, allow_redirects=True)
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

        _cache_set(cache_key, security_info)
        return security_info
    except Exception as e:
        result = {"error": str(e)}
        _cache_set(cache_key, result)
        return result

def compute_security_score(http_headers):
    if not isinstance(http_headers, dict) or http_headers.get('error'):
        return 0
    score = 0
    if 'HSTS' in http_headers:
        score += 3
    if 'X-Content-Type-Options' in http_headers:
        score += 2
    if 'X-Frame-Options' in http_headers:
        score += 2
    if 'X-XSS-Protection' in http_headers:
        score += 1
    if 'CSP' in http_headers:
        score += 2
    return score

SECURITY_HEADERS_CATALOG = [
    {
        'key': 'HSTS',
        'protects': 'перехват HTTP-трафика, downgrade-атаки и MITM при повторных визитах',
        'recommend': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    {
        'key': 'CSP',
        'protects': 'XSS, инъекции скриптов и загрузку ресурсов с недоверенных доменов',
        'recommend': 'Content-Security-Policy с ограничением script-src, default-src и запретом unsafe-inline',
    },
    {
        'key': 'X-Frame-Options',
        'protects': 'clickjacking — встраивание сайта во фрейм злоумышленника',
        'recommend': 'X-Frame-Options: DENY или SAMEORIGIN',
    },
    {
        'key': 'X-Content-Type-Options',
        'protects': 'MIME-sniffing — подмену типа файла браузером',
        'recommend': 'X-Content-Type-Options: nosniff',
    },
    {
        'key': 'Referrer-Policy',
        'protects': 'утечку URL и параметров через заголовок Referer на сторонние сайты',
        'recommend': 'Referrer-Policy: strict-origin-when-cross-origin или no-referrer',
    },
    {
        'key': 'X-XSS-Protection',
        'protects': 'отражённый XSS в устаревших браузерах (legacy)',
        'recommend': 'X-XSS-Protection: 1; mode=block — или полагайтесь на CSP в современных браузерах',
    },
]

def build_security_headers_report(http_headers):
    if not isinstance(http_headers, dict) or http_headers.get('error'):
        return None
    present = []
    missing = []
    for item in SECURITY_HEADERS_CATALOG:
        entry = dict(item)
        if item['key'] in http_headers:
            entry['value'] = http_headers[item['key']]
            present.append(entry)
        else:
            missing.append(entry)
    return {
        'present': present,
        'missing': missing,
        'present_count': len(present),
        'missing_count': len(missing),
        'total': len(SECURITY_HEADERS_CATALOG),
    }

def check_mobile_optimization(url):
    """Check mobile optimization indicators"""
    try:
        response = http_get(url)
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
                response = http_get(url, allow_redirects=True, stream=True)
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

def calculate_seo_score_enhanced(load_time, avg_ping, dns_info, ssl_info, url, http_headers,
                                 meta_seo=None, robots_sitemap=None, redirect_info=None):
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
    if _ssl_is_valid(ssl_info):
        score += 10
        if isinstance(ssl_info, dict) and ssl_info.get('days_remaining') is not None:
            days = ssl_info['days_remaining']
            if days <= 30:
                details.append(f"🔒 SSL действителен, но истекает через {days} дн.")
            else:
                details.append(f"🔒 SSL сертификат валиден ({ssl_info.get('issuer', '')})")
        else:
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
    security_score = compute_security_score(http_headers)
    security_details = []
    if isinstance(http_headers, dict) and "error" not in http_headers:
        for header in ('HSTS', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection', 'CSP'):
            if header in http_headers:
                security_details.append(header)

    score += security_score
    
    if security_score >= 8:
        details.append("🛡️ Отличная безопасность (все заголовки)")
    elif security_score >= 5:
        details.append(f"🛡️ Хорошая безопасность ({', '.join(security_details)})")
    elif security_score >= 2:
        details.append(f"🛡️ Базовая безопасность ({', '.join(security_details)})")
    else:
        details.append("🛡️ Требуется улучшение безопасности")

    # Content SEO checks (informational + up to 10 bonus points)
    if meta_seo:
        if meta_seo['title']['present']:
            if meta_seo['title']['status'] == 'ok':
                score += 3
                details.append(f"📝 Title: OK ({meta_seo['title']['length']} симв.)")
            else:
                score += 1
                details.append(f"📝 Title: требует доработки ({meta_seo['title']['length']} симв.)")
        else:
            details.append("📝 Title: отсутствует")

        if meta_seo['description']['present']:
            if meta_seo['description']['status'] == 'ok':
                score += 3
                details.append(f"📄 Description: OK ({meta_seo['description']['length']} симв.)")
            else:
                score += 1
                details.append(f"📄 Description: требует доработки ({meta_seo['description']['length']} симв.)")
        else:
            details.append("📄 Description: отсутствует")

        if meta_seo['canonical']['present']:
            score += 1
            details.append("🔗 Canonical: присутствует")
        else:
            details.append("🔗 Canonical: отсутствует")

        og = meta_seo['og']['status']
        og_score = meta_seo['og']['score']
        if og == 'ok':
            score += 2
            details.append(f"📱 Open Graph: {og_score}")
        elif og == 'partial':
            score += 1
            details.append(f"📱 Open Graph: {og_score}")
        else:
            details.append("📱 Open Graph: 0/4")

    if robots_sitemap:
        robots = robots_sitemap['robots']
        if robots['present']:
            if robots.get('blocks_indexing'):
                details.append("⚠️ robots.txt блокирует индексацию (Disallow: /)")
            else:
                score += 1
                details.append("🤖 robots.txt: найден")
        else:
            details.append("🤖 robots.txt: отсутствует")
        sitemap = robots_sitemap['sitemap']
        if sitemap['present']:
            score += 1
            found = sitemap.get('found_url') or sitemap.get('url')
            details.append(f"🗺️ Sitemap: найден ({found})")
        else:
            details.append("🗺️ Sitemap: не найден")

    if redirect_info and not redirect_info.get('error'):
        code = redirect_info.get('status_code')
        redirects = redirect_info.get('redirect_count', 0)
        if code and code < 400:
            details.append(f"🌐 HTTP {code} {redirect_info.get('status_text', '')}" +
                           (f", редиректов: {redirects}" if redirects else ""))
        if redirect_info.get('http_to_https'):
            details.append("🔐 HTTP → HTTPS редирект настроен")
        if redirect_info.get('has_cycle'):
            details.append("⚠️ Обнаружен циклический редирект")
        elif redirect_info.get('chain_too_long'):
            details.append("⚠️ Слишком длинная цепочка редиректов (>3)")

    score = min(score, 100)

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

def build_audit_snapshot(seo_score_value, security_score, http_headers, meta_seo,
                         robots_sitemap, redirect_info, compression_info,
                         page_size_info, headings_info, images_info):
    """Compact audit data for history detail modal."""
    headers_report = build_security_headers_report(http_headers)
    title = (meta_seo or {}).get('title', {})
    desc = (meta_seo or {}).get('description', {})
    og = (meta_seo or {}).get('og', {})
    robots = (robots_sitemap or {}).get('robots', {})
    sitemap = (robots_sitemap or {}).get('sitemap', {})
    compression = compression_info or {}

    snapshot = {
        'seo_score_value': seo_score_value,
        'security_score': security_score,
        'security_score_max': SECURITY_SCORE_MAX,
        'security_headers_present': headers_report['present_count'] if headers_report else None,
        'security_headers_total': headers_report['total'] if headers_report else None,
        'security_headers_ok': [h['key'] for h in headers_report['present']] if headers_report else [],
        'security_headers_missing': [h['key'] for h in headers_report['missing']] if headers_report else [],
        'redirect_count': redirect_info.get('redirect_count') if redirect_info else None,
        'http_to_https': redirect_info.get('http_to_https') if redirect_info else None,
        'http_status': redirect_info.get('status_code') if redirect_info else None,
        'final_url': redirect_info.get('final_url') if redirect_info else None,
        'page_size_display': page_size_info.get('display') if page_size_info else None,
        'page_size_recommendation': page_size_info.get('recommendation') if page_size_info else None,
        'compression': compression.get('display') if compression else None,
        'title': (title.get('text') or '')[:120] or None,
        'title_length': title.get('length'),
        'title_status': title.get('status'),
        'description_length': desc.get('length'),
        'description_status': desc.get('status'),
        'og_score': og.get('score'),
        'robots_present': robots.get('present'),
        'robots_blocks_indexing': robots.get('blocks_indexing'),
        'sitemap_present': sitemap.get('present'),
        'h1_count': (headings_info or {}).get('h1_count'),
        'h2_count': (headings_info or {}).get('h2_count'),
        'images_total': (images_info or {}).get('total'),
        'images_missing_alt': (images_info or {}).get('missing_alt'),
    }
    return snapshot

def save_analysis(url, load_time, dns_info, ssl_info, avg_ping, ping_result, page_size, seo_score, security_score=None, audit_snapshot=None):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    seo_score_numeric = convert_seo_to_numeric(seo_score)
    ssl_days_remaining = ssl_info.get('days_remaining') if isinstance(ssl_info, dict) else None
    snapshot_json = json.dumps(audit_snapshot, ensure_ascii=False) if audit_snapshot else None

    with db_session(write=True) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO analysis_history
            (url, load_time, dns_info, ssl_info, avg_ping, ping_result, page_size, seo_score,
             seo_score_numeric, domain, last_check_date, ssl_days_remaining, security_score,
             audit_snapshot)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?)
        ''', (url, load_time, dns_info, str(ssl_info) if isinstance(ssl_info, dict) else ssl_info,
              avg_ping, ping_result, page_size, seo_score, seo_score_numeric, domain,
              ssl_days_remaining, security_score, snapshot_json))
        check_for_degradation(url, seo_score_numeric, load_time, cursor)

def convert_seo_to_numeric(seo_score):
    """Конвертирует буквенный SEO рейтинг в числовое значение"""
    score_map = {
        'S+': 100, 'S': 95, 'A+': 90, 'A': 85, 'A-': 80,
        'B+': 75, 'B': 70, 'B-': 65, 'C+': 60, 'C': 55,
        'C-': 50, 'D+': 45, 'D': 40, 'D-': 35, 'F': 30
    }
    return score_map.get(seo_score, 0)

def _normalize_history_record(record):
    record['is_favorite'] = bool(record.get('is_favorite'))
    raw_snapshot = record.get('audit_snapshot')
    if isinstance(raw_snapshot, str) and raw_snapshot:
        try:
            record['audit_snapshot'] = json.loads(raw_snapshot)
        except json.JSONDecodeError:
            record['audit_snapshot'] = None
    return record

def check_for_degradation(url, current_score, current_load_time, cursor):
    """Проверяет ухудшение показателей и создает алерты (тот же cursor, что у save_analysis)."""
    cursor.execute('''
        SELECT seo_score_numeric, load_time FROM analysis_history
        WHERE url = ? AND id != (SELECT MAX(id) FROM analysis_history WHERE url = ?)
        ORDER BY timestamp DESC LIMIT 1
    ''', (url, url))

    result = cursor.fetchone()
    if not result:
        return

    prev_score, prev_load_time = result

    if current_score < prev_score - 10:
        cursor.execute('''
            INSERT INTO alerts (url, alert_type, message)
            VALUES (?, 'seo_degradation', ?)
        ''', (url, f'SEO рейтинг ухудшился с {prev_score} до {current_score}'))

    if current_load_time and prev_load_time and current_load_time > prev_load_time * 1.5:
        cursor.execute('''
            INSERT INTO alerts (url, alert_type, message)
            VALUES (?, 'performance_degradation', ?)
        ''', (url, f'Время загрузки увеличилось с {prev_load_time:.3f}s до {current_load_time:.3f}s'))

def get_analysis_history(limit=10):
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM analysis_history
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
    
    # Convert to list of dictionaries with all new fields
    columns = ['id', 'url', 'load_time', 'dns_info', 'ssl_info', 'avg_ping', 'ping_result', 'page_size',
               'seo_score', 'seo_score_numeric', 'timestamp', 'is_favorite', 'tags', 'notes', 'domain',
               'last_check_date', 'ssl_days_remaining', 'security_score', 'audit_snapshot']
    
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

    for record in history:
        _normalize_history_record(record)

    return enrich_history_with_deltas(history)

def get_previous_analysis(url):
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT seo_score_numeric, load_time, seo_score, timestamp, ssl_days_remaining, security_score
            FROM analysis_history WHERE url = ?
            ORDER BY timestamp DESC LIMIT 1
        ''', (url,))
        row = cursor.fetchone()
    if not row:
        return None
    return {
        'seo_score_numeric': row[0],
        'load_time': row[1],
        'seo_score': row[2],
        'timestamp': row[3],
        'ssl_days_remaining': row[4],
        'security_score': row[5],
    }

def build_analysis_comparison(previous, seo_score_value, load_time, ssl_days=None, security_score=None):
    if not previous:
        return None
    prev_seo = previous.get('seo_score_numeric') or 0
    prev_load = previous.get('load_time') or 0
    seo_delta = seo_score_value - prev_seo
    load_delta = load_time - prev_load
    load_pct = round((load_delta / prev_load) * 100, 1) if prev_load else None

    prev_ssl = previous.get('ssl_days_remaining')
    ssl_delta = None
    if prev_ssl is not None and ssl_days is not None:
        ssl_delta = ssl_days - prev_ssl

    prev_security = previous.get('security_score')
    security_delta = None
    if prev_security is not None and security_score is not None:
        security_delta = security_score - prev_security

    return {
        'previous_seo_score': prev_seo,
        'previous_seo_grade': previous.get('seo_score'),
        'seo_delta': seo_delta,
        'previous_load_time': prev_load,
        'load_time_delta': load_delta,
        'load_time_delta_pct': load_pct,
        'previous_timestamp': previous.get('timestamp'),
        'previous_ssl_days': prev_ssl,
        'ssl_days': ssl_days,
        'ssl_days_delta': ssl_delta,
        'previous_security_score': prev_security,
        'security_score': security_score,
        'security_delta': security_delta,
        'security_score_max': SECURITY_SCORE_MAX,
    }

def enrich_history_with_deltas(history):
    from collections import defaultdict
    by_url = defaultdict(list)
    for item in history:
        by_url[item['url']].append(item)
    for records in by_url.values():
        records.sort(key=lambda x: x.get('timestamp') or '', reverse=True)
        for i, record in enumerate(records):
            if i + 1 < len(records):
                older = records[i + 1]
                curr_seo = record.get('seo_score_numeric') or 0
                old_seo = older.get('seo_score_numeric') or 0
                record['seo_delta'] = curr_seo - old_seo
                curr_load = record.get('load_time') or 0
                old_load = older.get('load_time') or 0
                record['load_time_delta'] = curr_load - old_load
                record['load_time_delta_pct'] = round(((curr_load - old_load) / old_load) * 100, 1) if old_load else None
                curr_ssl = record.get('ssl_days_remaining')
                old_ssl = older.get('ssl_days_remaining')
                record['ssl_days_delta'] = (curr_ssl - old_ssl) if curr_ssl is not None and old_ssl is not None else None
                curr_sec = record.get('security_score')
                old_sec = older.get('security_score')
                record['security_delta'] = (curr_sec - old_sec) if curr_sec is not None and old_sec is not None else None
            else:
                record['seo_delta'] = None
                record['load_time_delta'] = None
                record['load_time_delta_pct'] = None
                record['ssl_days_delta'] = None
                record['security_delta'] = None
    return history

def run_parallel_checks(fetch_url):
    worker_count = min(MAX_PARALLEL_WORKERS, 5)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            'dns_info': executor.submit(get_dns_info, fetch_url),
            'ssl_info': executor.submit(get_ssl_info, fetch_url),
            'http_headers': executor.submit(get_http_headers, fetch_url),
            'robots_sitemap': executor.submit(check_robots_sitemap, fetch_url),
            'ping': executor.submit(ping_url, fetch_url),
        }
        results = {key: future.result() for key, future in futures.items()}
    avg_ping, ping_result = results.pop('ping')
    results['avg_ping'] = avg_ping
    results['ping_result'] = ping_result
    return results

def clear_analysis_history():
    with db_session(write=True) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM analysis_history')
        deleted_count = cursor.rowcount
    return deleted_count

def delete_analysis_by_id(analysis_id):
    with db_session(write=True) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM analysis_history WHERE id = ?', (analysis_id,))
        deleted_count = cursor.rowcount
    return deleted_count

@app.template_filter('detail_status')
def detail_status(text):
    if not text:
        return 'info'
    if '❌' in str(text):
        return 'error'
    if '⚠️' in str(text):
        return 'warn'
    return 'ok'

@app.template_filter('detail_status_label')
def detail_status_label(text):
    labels = {'ok': 'OK', 'warn': 'Внимание', 'error': 'Ошибка', 'info': 'Инфо'}
    return labels[detail_status(text)]

@app.template_filter('clean_detail')
def clean_detail(text):
    if not text:
        return ''
    s = str(text).strip()
    parts = re.split(r'(?=[A-Za-zА-Яа-яЁё0-9])', s, maxsplit=1)
    return parts[-1].strip() if parts else s

@app.context_processor
def inject_globals():
    return {'app_version': APP_VERSION}

def get_landing_sample_report():
    """Demo report for landing preview — grades/scores match calculate_seo_score_enhanced()."""
    return {
        'url': 'https://example.com',
        'load_time': 0.842,
        'dns_info': '93.184.216.34',
        'ssl_info': {
            'valid': True,
            'status': 'ok',
            'days_remaining': 89,
            'issuer': "Let's Encrypt",
            'expires': '15.09.2026',
        },
        'avg_ping': '42',
        'ping_via_http': False,
        'page_size_info': {
            'display': '1.2 MB',
            'status': 'warning',
            'recommendation': 'Рекомендуется уменьшить размер ниже 1 MB',
        },
        'redirect_info': {
            'status_code': 200,
            'status_text': 'OK',
            'redirect_count': 1,
            'http_to_https': True,
        },
        'meta_seo': {
            'title': {'status': 'ok', 'hint': 'Good', 'length': 52},
        },
        'robots_sitemap': {
            'robots': {'status': 'ok', 'blocks_indexing': False},
        },
        'headings_info': {'h1_count': 1},
        'seo_grade': 'B+',
        'seo_score_value': 74,
        'seo_feedback': '✅ ХОРОШИЙ РЕЗУЛЬТАТ! Есть небольшие возможности для улучшения!',
    }

def _landing_context(**kwargs):
    kwargs.setdefault('sample', get_landing_sample_report())
    return kwargs

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        client_ip = get_client_ip()
        started_at = time.time()
        cache_hits_before = get_cache_stats()['hits']

        if not is_valid_url(url):
            duration_ms = int((time.time() - started_at) * 1000)
            record_analysis(duration_ms, success=False)
            log_analysis_event(url, duration_ms, False, 'invalid_url', client_ip=client_ip)
            return render_template('index.html', **_landing_context(error="Неверный URL"))

        allowed, used = try_consume_daily_quota(client_ip)
        if not allowed:
            duration_ms = int((time.time() - started_at) * 1000)
            record_analysis(duration_ms, success=False)
            log_analysis_event(
                url, duration_ms, False, 'rate_limited',
                error=f'daily_limit_{FREE_DAILY_LIMIT}', client_ip=client_ip)
            return render_template(
                'index.html',
                **_landing_context(
                    error=f"Достигнут лимит Free-плана: {FREE_DAILY_LIMIT} анализов в сутки "
                          f"({used}/{FREE_DAILY_LIMIT}). Pro — без лимита."))

        try:
            redirect_info = analyze_redirects(url)
            fetch_url = redirect_info.get('final_url') or url

            page_data = fetch_page_content(fetch_url)
            if page_data.get('error'):
                duration_ms = int((time.time() - started_at) * 1000)
                cache_hit = get_cache_stats()['hits'] > cache_hits_before
                record_analysis(duration_ms, success=False)
                log_analysis_event(
                    url, duration_ms, cache_hit, 'error',
                    error=page_data['error'], client_ip=client_ip)
                return render_template('index.html', **_landing_context(error="Не удалось загрузить сайт"))

            load_time = page_data['load_time']
            page_size = page_data['size_bytes']
            html = page_data['html']
            compression_info = page_data['compression']
            page_size_info = format_page_size_info(page_size)

            meta_seo = analyze_meta_seo(html)
            headings_info = analyze_headings(html)
            images_info = analyze_images(html)

            parallel = run_parallel_checks(fetch_url)
            dns_info = parallel['dns_info']
            ssl_info = parallel['ssl_info']
            http_headers = parallel['http_headers']
            robots_sitemap = parallel['robots_sitemap']
            avg_ping = parallel['avg_ping']
            ping_result = parallel['ping_result']

            seo_grade, seo_feedback, seo_details, seo_score_value = calculate_seo_score_enhanced(
                load_time, avg_ping, dns_info, ssl_info, url, http_headers,
                meta_seo, robots_sitemap, redirect_info)

            security_score = compute_security_score(http_headers)
            ssl_days = ssl_info.get('days_remaining') if isinstance(ssl_info, dict) else None

            previous = get_previous_analysis(url)
            comparison = build_analysis_comparison(
                previous, seo_score_value, load_time, ssl_days, security_score)

            audit_snapshot = build_audit_snapshot(
                seo_score_value, security_score, http_headers, meta_seo,
                robots_sitemap, redirect_info, compression_info,
                page_size_info, headings_info, images_info)

            save_analysis(url, load_time, dns_info, ssl_info, avg_ping, ping_result,
                          page_size, seo_grade, security_score=security_score,
                          audit_snapshot=audit_snapshot)

            duration_ms = int((time.time() - started_at) * 1000)
            cache_hit = get_cache_stats()['hits'] > cache_hits_before
            record_analysis(duration_ms, success=True)
            log_analysis_event(url, duration_ms, cache_hit, 'success', client_ip=client_ip)

            return render_template('result.html',
                                url=url,
                                fetch_url=fetch_url,
                                load_time=load_time,
                                dns_info=dns_info,
                                ssl_info=ssl_info,
                                avg_ping=avg_ping,
                                ping_result=ping_result,
                                page_size=page_size,
                                page_size_info=page_size_info,
                                compression_info=compression_info,
                                redirect_info=redirect_info,
                                meta_seo=meta_seo,
                                robots_sitemap=robots_sitemap,
                                headings_info=headings_info,
                                images_info=images_info,
                                seo_grade=seo_grade,
                                seo_feedback=seo_feedback,
                                seo_details=seo_details,
                                seo_score_value=seo_score_value,
                                http_headers=http_headers,
                                security_headers_report=build_security_headers_report(http_headers),
                                comparison=comparison)
        except Exception as exc:
            duration_ms = int((time.time() - started_at) * 1000)
            cache_hit = get_cache_stats()['hits'] > cache_hits_before
            record_analysis(duration_ms, success=False)
            log_analysis_event(
                url, duration_ms, cache_hit, 'error',
                error=str(exc), client_ip=client_ip)
            raise
    return render_template('index.html', **_landing_context())

# API Endpoints

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

@app.route('/version')
def version():
    return jsonify({'version': APP_VERSION})

@app.route('/api')
def api_overview():
    return render_template('api.html')

@app.route('/docs')
def docs():
    return render_template('docs.html', free_daily_limit=FREE_DAILY_LIMIT)

@app.route('/api/history', methods=['GET'])
def api_history():
    limit = request.args.get('limit', 10, type=int)
    history = get_analysis_history(limit)
    return jsonify(history)

@app.route('/api/stats', methods=['GET'])
def api_stats():
    with db_session() as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM analysis_history')
        total_analyses = cursor.fetchone()[0]

        cursor.execute('SELECT AVG(load_time) FROM analysis_history WHERE load_time IS NOT NULL')
        avg_load_time = cursor.fetchone()[0] or 0

        cursor.execute('''
            SELECT url, COUNT(*) as count
            FROM analysis_history
            GROUP BY url
            ORDER BY count DESC
            LIMIT 5
        ''')
        top_urls = [{'url': row[0], 'count': row[1]} for row in cursor.fetchall()]

    public_stats = {
        'total_analyses': total_analyses,
        'average_load_time': round(avg_load_time, 3),
        'top_urls': top_urls,
    }
    if not admin_stats_allowed():
        return jsonify(public_stats)

    runtime = get_runtime_metrics()
    return jsonify({
        **public_stats,
        'cache': get_cache_stats(),
        'analysis_count': runtime['analysis_count'],
        'avg_duration_ms': runtime['avg_duration_ms'],
        'error_rate': runtime['error_rate'],
        'success_count': runtime['success_count'],
        'error_count': runtime['error_count'],
        'free_daily_limit': FREE_DAILY_LIMIT,
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

        with db_session() as conn:
            cursor = conn.cursor()

            query = '''
                SELECT * FROM analysis_history WHERE 1=1
            '''
            params = []

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
        
        # Конвертируем в список словарей
        columns = ['id', 'url', 'load_time', 'dns_info', 'ssl_info', 'avg_ping', 'ping_result', 'page_size',
               'seo_score', 'seo_score_numeric', 'timestamp', 'is_favorite', 'tags', 'notes', 'domain',
               'last_check_date', 'ssl_days_remaining', 'security_score', 'audit_snapshot']
        history = [dict(zip(columns, row)) for row in results]
        for record in history:
            _normalize_history_record(record)

        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Расширенная аналитика"""
    try:
        with db_session() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT seo_score, COUNT(*) as count
                FROM analysis_history
                GROUP BY seo_score
                ORDER BY seo_score_numeric DESC
            ''')
            seo_distribution = [{'score': row[0], 'count': row[1]} for row in cursor.fetchall()]

            cursor.execute('''
                SELECT domain, COUNT(*) as count, AVG(seo_score_numeric) as avg_score
                FROM analysis_history
                WHERE domain IS NOT NULL
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 10
            ''')
            top_domains = [{'domain': row[0], 'count': row[1], 'avg_score': round(row[2], 1)} for row in cursor.fetchall()]

            cursor.execute('''
                SELECT DATE(timestamp) as date, AVG(seo_score_numeric) as avg_score
                FROM analysis_history
                WHERE timestamp >= DATE('now', '-30 days')
                GROUP BY DATE(timestamp)
                ORDER BY date
            ''')
            seo_trend = [{'date': row[0], 'avg_score': round(row[1], 1)} for row in cursor.fetchall()]

            cursor.execute('''
                SELECT
                    COUNT(CASE WHEN load_time < 1 THEN 1 END) as fast,
                    COUNT(CASE WHEN load_time >= 1 AND load_time < 3 THEN 1 END) as medium,
                    COUNT(CASE WHEN load_time >= 3 THEN 1 END) as slow
                FROM analysis_history
                WHERE load_time IS NOT NULL
            ''')
            load_time_stats = cursor.fetchone()

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
        is_favorite = 1 if data.get('is_favorite') else 0

        with db_session(write=True) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE analysis_history SET is_favorite = ? WHERE id = ?', (is_favorite, analysis_id))

        return jsonify({'success': True, 'is_favorite': bool(is_favorite)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/alerts', methods=['GET', 'POST'])
def api_alerts():
    """Управление алертами"""
    try:
        if request.method == 'GET':
            with db_session() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50')
                alerts = cursor.fetchall()
            columns = ['id', 'url', 'alert_type', 'message', 'is_read', 'created_at']
            return jsonify([dict(zip(columns, row)) for row in alerts])

        data = request.get_json()
        alert_id = data.get('alert_id')
        with db_session(write=True) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE alerts SET is_read = 1 WHERE id = ?', (alert_id,))

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<format>')
def api_export(format):
    """Экспорт данных в разных форматах"""
    try:
        with db_session() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM analysis_history ORDER BY timestamp DESC')
            results = cursor.fetchall()

        columns = ['id', 'url', 'load_time', 'dns_info', 'ssl_info', 'avg_ping', 'ping_result', 'page_size',
               'seo_score', 'seo_score_numeric', 'timestamp', 'is_favorite', 'tags', 'notes', 'domain',
               'last_check_date', 'ssl_days_remaining', 'security_score', 'audit_snapshot']
        
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