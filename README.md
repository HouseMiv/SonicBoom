# SonicBoom

**Open-source веб-сервис технического аудита сайтов** — проверка производительности, SEO, SSL, DNS, security headers и смежных параметров с историей проверок и REST API.

> В интерфейсе бренд отображается как **Sonic Boom** (`SB`).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`Python` `Flask` `HTML` `CSS` `JavaScript` `requests` `SQLite` `Jinja2` `Gunicorn`  
`socket` `ssl` `subprocess` `Chart.js` `Font Awesome`

---

## О проекте

SonicBoom — self-hosted инструмент для быстрого снимка «здоровья» сайта: один URL → отчёт с оценкой, детализацией и сохранением в историю. Подходит для разработчиков, SEO-специалистов и команд, которым нужен лёгкий аудит без тяжёлого стека.

**Не заменяет:** полноценный pentest, Lighthouse CI или мониторинг 24/7 — даёт оперативную картину по ключевым техническим сигналам.

---

## Возможности

### 12 параметров технического аудита

| # | Параметр | Что проверяется |
|---|----------|-----------------|
| 01 | **SSL** | Сертификат, срок, SAN, издатель; понятное описание ошибок |
| 02 | **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, X-XSS-Protection — «защищает от» / «можно добавить» |
| 03 | **SEO Audit** | Сводная оценка 0–100 и буквенный рейтинг (S+ … F) |
| 04 | **Meta Tags** | Title, description, canonical, Open Graph |
| 05 | **Redirects** | Цепочка редиректов, HTTP → HTTPS |
| 06 | **Robots & Sitemap** | robots.txt, sitemap.xml, блокировка индексации |
| 07 | **Performance** | Время загрузки, размер страницы |
| 08 | **DNS** | Резолвинг домена и IP |
| 09 | **Latency** | Ping (ICMP) или HTTP-задержка как fallback |
| 10 | **Images** | Наличие ALT у изображений |
| 11 | **Compression** | Gzip / Brotli / Deflate |
| 12 | **History** | История проверок и сравнение с прошлым анализом |

### Страница результата

- Hero с SEO-рейтингом и числовым баллом
- Список результатов анализа со статусами (OK / Внимание / Ошибка)
- Блок security headers: **настроено — защищает от** и **можно добавить**
- Сравнение с предыдущим анализом того же URL (SEO, load time, SSL, security score)
- Сворачиваемые длинные значения (CSP и др.)

### Лендинг

- Сетка «12 параметров технического аудита»
- **Пример отчёта** — превью в стиле реальной страницы результата
- Единый footer: Version · API · Documentation · GitHub

### История и аналитика (`/history`)

**Таблица истории**

- Избранное, удаление записи, повторный анализ, экспорт CSV/JSON
- Колонка «Изменения» — дельты SEO, load time, SSL, security vs прошлая проверка
- Поиск по URL, фильтры (дата, SEO, load time, домен, теги, избранное)

**Модальное окно «Детали анализа»**

- Метрики: SEO, security score, загрузка, ping, размер, DNS
- SSL: поля сертификата или **Причина** + раскрываемая техническая ошибка
- **SEO и аудит** из `audit_snapshot` (meta, redirects, robots, sitemap, H1/H2, images, compression)
- Security headers: сводка `N из 6`, строки **Настроено** (зелёные теги) и **Отсутствует** (красные)
- Блок «Изменения vs прошлый анализ» при наличии предыдущей записи

**Аналитика**

- Распределение SEO-рейтингов
- Buckets времени загрузки (fast / medium / slow)
- Топ доменов по числу анализов
- Тренд среднего SEO за 30 дней

**Алерты**

- Ухудшение SEO более чем на 10 баллов
- Рост времени загрузки более чем в 1.5×

### API и документация

- REST API: история, фильтры, статистика, аналитика, избранное, алерты, экспорт
- [`/docs`](http://127.0.0.1:5000/docs) — интерактивная документация
- [`/api`](http://127.0.0.1:5000/api) — обзор эндпоинтов
- `GET /health` — health-check
- `GET /version` — версия приложения

---

## Быстрый старт

### Требования

- Python **3.10+** (протестировано на 3.11–3.13)
- pip
- Для ping на Windows — права на ICMP; при недоступности используется HTTP-latency

### Установка

```bash
git clone https://github.com/YOUR_USERNAME/SonicBoom.git
cd SonicBoom

python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Запуск (разработка)

```bash
python app.py
```

Откройте: **http://127.0.0.1:5000/**

При первом запуске создаётся SQLite-база `sonic_boom.db` (режим **WAL**, доступ через потокобезопасный `db_session`).

> **SQLite:** не держите `sonic_boom.db` открытым в DB Browser во время работы сервера. При `debug=True` reloader создаёт второй процесс — при блокировках закройте редактор БД или запустите с `use_reloader=False`.

---

## Конфигурация

Переменные окружения (пример для продакшена: [`deploy/env.example`](deploy/env.example)):

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `APP_VERSION` | `1.0.0-beta` | Версия в UI и API |
| `DB_PATH` | `sonic_boom.db` | Путь к SQLite |
| `DB_TIMEOUT` | `30` | Таймаут ожидания блокировки БД (сек) |
| `FREE_DAILY_LIMIT` | `20` | Лимит анализов в сутки на IP (`127.0.0.1`, `::1` — без лимита) |
| `CACHE_TTL_SECONDS` | `300` | TTL кэша DNS / SSL / headers |
| `CACHE_MAX_ENTRIES` | `1000` | Максимум записей в in-memory кэше |
| `MAX_PARALLEL_WORKERS` | `min(8, cpu×2)` | Параллельные проверки при анализе |
| `STATS_ADMIN_TOKEN` | — | Расширенная статистика (`X-Admin-Token` или `?token=`) |
| `LOG_DIR` | `logs` | Каталог логов |
| `LOG_MAX_BYTES` | `10485760` | Ротация `analysis.log` |
| `LOG_BACKUP_COUNT` | `5` | Число архивных логов |

---

## Структура проекта

```
SonicBoom/
├── app.py                      # Flask, анализ, scoring, API, SQLite
├── requirements.txt
├── sonic_boom.db               # БД (создаётся автоматически; не коммитить)
├── deploy/
│   ├── env.example             # Пример env для сервера
│   └── sonic-boom.service      # systemd unit (Gunicorn)
├── scripts/
│   ├── gunicorn_start.sh       # Запуск Gunicorn
│   └── load_test.py            # Нагрузочный тест
├── static/css/
│   ├── nav.css
│   ├── footer.css
│   └── report-preview.css
├── templates/
│   ├── index.html              # Лендинг + форма анализа
│   ├── result.html             # Отчёт
│   ├── history.html            # История и аналитика
│   ├── docs.html               # Документация API
│   ├── api.html                # Обзор API
│   ├── partials/               # footer, landing_report_preview
│   ├── 404.html
│   └── 500.html
└── logs/                       # analysis.log (создаётся автоматически)
```

---

## API (кратко)

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/` | Запуск анализа (form field: `url`) |
| `GET` | `/history` | Страница истории |
| `GET` | `/api/history?limit=N` | JSON истории |
| `GET` | `/api/history/filter` | Фильтрация (дата, SEO, load time, домен, избранное, теги) |
| `GET` | `/api/stats` | Сводная статистика |
| `GET` | `/api/analytics` | Данные для графиков |
| `POST` | `/api/favorites` | Переключить избранное |
| `GET` / `POST` | `/api/alerts` | Список алертов / отметить прочитанным |
| `GET` | `/api/export/csv` · `/api/export/json` | Экспорт истории |
| `DELETE` | `/api/delete-analysis/<id>` | Удалить запись |
| `DELETE` | `/api/clear-history` | Очистить всю историю |

Параметры, примеры запросов и лимиты — на **/docs**.

---

## Данные в SQLite

Таблица `analysis_history` хранит основные метрики и JSON-снимок **`audit_snapshot`** (meta, redirects, robots, security headers, headings, images и т.д.) для детального просмотра в истории.

Таблица `alerts` — уведомления о деградации. Таблица `daily_usage` — суточные квоты по IP.

---

## Продакшен

### Gunicorn

```bash
chmod +x scripts/gunicorn_start.sh
./scripts/gunicorn_start.sh
```

Или вручную:

```bash
gunicorn --workers 2 --bind 127.0.0.1:8000 --timeout 120 app:app
```

### systemd + reverse proxy

Пример unit: [`deploy/sonic-boom.service`](deploy/sonic-boom.service). Рекомендуется Nginx (или аналог) для TLS и раздачи статики.

---

## Архитектура

| Слой | Технологии |
|------|------------|
| Backend | Flask 3, SQLite (WAL), `db_session` + lock |
| Frontend | HTML, CSS, JavaScript, Chart.js, Font Awesome |
| Анализ | `requests`, `ThreadPoolExecutor` (DNS, SSL, headers, robots/sitemap, ping) |
| Кэш | In-memory TTL для повторных проверок одного домена |
| Логи | JSON-события в `logs/analysis.log` (IP маскируется) |

---

## Участие в проекте (Contributing)

Pull request'ы и issue приветствуются.

1. Fork репозитория
2. Ветка: `git checkout -b feature/my-feature`
3. Изменения с минимальным focused diff
4. Проверка: `python app.py` — анализ, история, API
5. Pull Request с описанием **зачем** нужно изменение

**Идеи для contribution:**

- Карточки аналитики: security score, SSL expiry, тренд load time
- API для редактирования тегов и заметок в истории
- Колонки Security / SSL (дней) в таблице истории
- pytest для scoring, `build_audit_snapshot`, API
- Docker Compose
- i18n (EN / RU)

---

## Безопасность и ответственное использование

- Анализируйте **только сайты, на проверку которых у вас есть право**
- Не коммитьте `.env`, `STATS_ADMIN_TOKEN`, `sonic_boom.db`, `logs/`
- Сообщения об уязвимостях — через [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories) (без публичного PoC)

### Рекомендуемый `.gitignore`

```
sonic_boom.db
sonic_boom.db-wal
sonic_boom.db-shm
__pycache__/
*.pyc
logs/
.env
venv/
```

---

## Лицензия

Распространяется под **[MIT](LICENSE)** — свободное использование, изменение и распространение с сохранением copyright notice.

```
Copyright (c) 2026 SonicBoom contributors
```

> Если файла `LICENSE` ещё нет в форке — добавьте [стандартный текст MIT](https://choosealicense.com/licenses/mit/).

---

## Благодарности

- [Flask](https://flask.palletsprojects.com/), [Chart.js](https://www.chartjs.org/), [Font Awesome](https://fontawesome.com/)
- Практики технического SEO-аудита и OWASP по security headers

**SonicBoom** — быстрый технический снимок сайта в одном месте.
