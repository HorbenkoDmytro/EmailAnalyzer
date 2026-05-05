# Phishing Email Analyzer

Інструмент для аналізу email-повідомлень (`.eml`) на наявність ознак фішингу.
Виконує перевірки автентифікації (SPF / DKIM / DMARC), витягує та аналізує
URL-адреси, перевіряє вкладення (хеші + VirusTotal), обчислює зважений
показник ризику та формує PDF-звіт.

Інструмент може використовуватися як інтерфейсом командного рядка (CLI),
так і HTTP API (FastAPI). Уся логіка аналізу зосереджена в одному
ядрі (`analyzer.engine`), яке однаково викликається з обох інтерфейсів.

---

## Зміст

1. [Можливості](#можливості)
2. [Архітектура](#архітектура)
3. [Встановлення](#встановлення)
4. [Конфігурація](#конфігурація)
5. [Використання CLI](#використання-cli)
6. [Використання HTTP API](#використання-http-api)
7. [Локальний (offline) режим](#локальний-offline-режим)
8. [Цілісність вихідного файлу](#цілісність-вихідного-файлу)
9. [Логіка оцінювання ризику](#логіка-оцінювання-ризику)
10. [Структура проєкту](#структура-проєкту)
11. [Тестування](#тестування)

---

## Можливості

- **Парсер `.eml`** — заголовки, відправник / отримувач, MIME-частини,
  вкладення.
- **SPF / DKIM / DMARC** — обробка заголовка `Authentication-Results`
  з опціональною перевіркою через DNS (`dnspython`).
- **Аналіз URL** — витягування з тексту й HTML (`BeautifulSoup`),
  виявлення IP-адрес замість доменів, скорочувачів URL, підозрілих
  TLD, punycode/homograph, невідповідності тексту посилання й
  фактичної URL-адреси.
- **Аналіз вкладень** — обчислення MD5 / SHA-1 / SHA-256, виявлення
  небезпечних розширень, подвійних розширень, невідповідності
  `Content-Type` і розширення.
- **Інтеграція з VirusTotal v3** — перевірка URL та файлових хешів;
  опційно — завантаження невідомих файлів на сканування.
- **Зважена оцінка ризику** — кожен індикатор має вагу (1–10);
  загальна сума мапиться у рівень: Low / Medium / High / Critical.
- **PDF-звіт** — багатосекційний документ із цілісністю файлу,
  метаданими, результатами автентифікації, аналізом URL та вкладень,
  списком індикаторів і рекомендаціями.
- **JSON-експорт** — повне машиночитане представлення результату.
- **Локальний (offline) режим** — повне відключення мережевих викликів
  (`--no-external` або `--local-only`).
- **Хеш цілісності** — для кожного аналізованого `.eml` файлу
  обчислюються MD5, SHA-1 та SHA-256, які зберігаються у звіті.

---

## Архітектура

```
                            +-------------------+
                            |   CLI (main.py)   |
                            +---------+---------+
                                      |
                                      v
+---------------+         +-------------------------+
| HTTP API      |         |   analyzer.engine        |
| (api/main.py) +-------->|  analyze_email_bytes()   |
+---------------+         +-----+--------+-----------+
                                |        |
       +------------------------+        +-----------------------+
       v                                                         v
+-------------+   +--------------+   +-------------+   +-------------------+
| parser      |   | auth_checks  |   | url_extractor|  | attachments       |
| (.eml→data) |   | (SPF/DKIM/   |   | (heuristics) |  | (hashes + VT      |
|             |   |  DMARC)      |   |              |  |  hash lookup)     |
+-------------+   +--------------+   +-------------+   +-------------------+
                                |
                                v
                         +-------------+
                         | indicators  |
                         | (scoring)   |
                         +------+------+
                                |
                                v
                         +-------------+
                         |  reporter   |
                         |  (PDF)      |
                         +-------------+
```

Конфігурація централізована у класі `analyzer.settings.Settings`. Усі
зовнішні I/O-операції (DNS, VirusTotal) проходять перевірку прапорців
у `Settings`, тому їх можна вимкнути одним викликом.

---

## Встановлення

Потрібен **Python 3.10+** (використовуються типи `list[str]` без
`from __future__ import annotations`).

```bash
git clone https://github.com/HorbenkoDmytro/EmailAnalyzer.git
cd EmailAnalyzer

python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Залежності:

| Бібліотека            | Призначення                          |
| --------------------- | ------------------------------------ |
| `dnspython`           | DNS-запити для SPF / DMARC          |
| `beautifulsoup4`      | Парсинг HTML-частини листів          |
| `requests`            | HTTP-клієнт для VirusTotal           |
| `reportlab`           | Генерація PDF-звітів                 |
| `rich`                | Кольорове виведення в терміналі      |
| `python-dotenv`       | Завантаження `.env`                  |
| `fastapi` + `uvicorn` | HTTP API                             |
| `pydantic`            | Валідація запитів і відповідей API   |
| `pytest`              | Тестування                           |

---

## Конфігурація

Створіть файл `.env` за прикладом [.env.example](.env.example):

```env
VT_API_KEY=ваш_virustotal_api_ключ
```

Інші змінні оточення (необов'язкові):

| Змінна                            | За замовчуванням | Опис                                    |
| --------------------------------- | ---------------- | --------------------------------------- |
| `ANALYZER_NO_EXTERNAL`            | `false`          | Вимкнути всі зовнішні мережеві виклики  |
| `ANALYZER_ENABLE_DNS`             | `true`           | Дозволити DNS-запити                    |
| `ANALYZER_ENABLE_VT`              | `true`           | Дозволити запити до VirusTotal          |
| `ANALYZER_VT_CHECK_URLS`          | `true`           | Перевіряти URL у VirusTotal             |
| `ANALYZER_VT_CHECK_ATTACHMENTS`   | `true`           | Перевіряти вкладення у VirusTotal       |
| `ANALYZER_VT_UPLOAD`              | `false`          | Завантажувати невідомі файли на VT      |

---

## Використання CLI

```bash
# Базовий аналіз
python main.py path/to/email.eml

# Своя назва PDF-файлу + ключ VirusTotal
python main.py email.eml --output report.pdf --vt-key YOUR_VT_KEY

# Повністю локально (без DNS, без VirusTotal)
python main.py email.eml --no-external

# Те саме з псевдонімом
python main.py email.eml --local-only

# JSON-вивід поряд із PDF, детальний терміналовий вивід
python main.py email.eml --json --verbose

# Завантажити невідомі вкладення на VirusTotal (повільно, витрачає квоту)
python main.py email.eml --vt-upload

# Без генерації PDF
python main.py email.eml --no-pdf --json
```

Прапорці:

| Прапорець             | Опис                                                          |
| --------------------- | ------------------------------------------------------------- |
| `-o, --output FILE`   | Шлях до PDF-звіту                                             |
| `--vt-key KEY`        | API-ключ VirusTotal (або `VT_API_KEY` у `.env`)               |
| `--no-vt`             | Не використовувати VirusTotal                                 |
| `--no-external`       | Вимкнути всі зовнішні виклики (DNS + VT). Включає `--no-vt`  |
| `--local-only`        | Псевдонім для `--no-external`                                |
| `--vt-upload`         | Завантажувати на VT файли, чий хеш невідомий                  |
| `--no-pdf`            | Не генерувати PDF                                             |
| `--json`              | Записати JSON-зведення поряд із PDF                          |
| `-v, --verbose`       | Детальніше виведення в терміналі                              |

### Приклад терміналового виведення

```
╭───── Phishing Email Analyzer ─────╮
│ Analyzing: tests/samples/phishing │
│ Mode: local-only (no DNS / no VT) │
╰───────────────────────────────────╯

· Hashing source bytes
· Parsing email
· Running auth checks (DNS off)
· Extracting URLs
· Analyzing attachments
· Computing risk score

Email Metadata
  From:         notify@amaz0n-delivery.tk
  Display Name: Amazon Shipping
  Subject:      ALERT: Your package could not be delivered ...

File Integrity
  File:    phishing.eml
  Size:    2,840 bytes
  SHA-256: 2a4b...e72f

Authentication Results
  SPF    FAIL    SPF FAILED — sending server is NOT authorised...
  DKIM   FAIL    DKIM signature verification FAILED for domain ...
  DMARC  FAIL    DMARC FAILED. Policy on failure: reject.

URLs (3 found, 3 suspicious)
  [SUSPICIOUS] http://bit.ly/track-pkg-9988
  [SUSPICIOUS] http://203.0.113.42/track/confirm.php
  [SUSPICIOUS] http://collect-info.xyz/submit.php

Attachments (0 found, 0 suspicious)
  No attachments.

╭─────── Analysis Summary ───────╮
│ RISK LEVEL: CRITICAL           │
│ Score: 76 | Indicators: 13     │
╰────────────────────────────────╯
```

---

## Використання HTTP API

Запуск сервера:

```bash
uvicorn api.main:app --reload --port 8000
```

Інтерактивна документація: <http://localhost:8000/docs>
(Swagger UI автоматично згенерований із Pydantic-схем.)

### Ендпоінти

#### `GET /health`

Перевірка активності сервісу.

```bash
curl http://localhost:8000/health
```

```json
{
  "status": "ok",
  "time": "2026-05-04T11:30:00.123456+00:00",
  "version": "1.0.0"
}
```

#### `POST /analyze`

Аналіз `.eml`-файлу. Підтримує синхронний (`mode=sync`) і асинхронний
(`mode=async`) режим.

**Синхронний режим** — повертає повний звіт у відповіді:

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@phishing.eml" \
  -F "mode=sync" \
  -F "no_external=true"
```

**Асинхронний режим** — ставить аналіз у чергу й повертає `job_id`:

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@phishing.eml" \
  -F "mode=async" \
  -F "vt_api_key=YOUR_KEY"
```

```json
{
  "job_id": "9b2f...c1",
  "status": "pending",
  "status_url": "/analyze/jobs/9b2f...c1"
}
```

#### `GET /analyze/jobs/{job_id}`

Отримати статус і результат асинхронної задачі:

```bash
curl http://localhost:8000/analyze/jobs/9b2f...c1
```

Можливі значення `status`: `pending`, `running`, `completed`, `failed`.
Коли `status=completed`, поле `result` містить повний об'єкт
`AnalysisResponse` (така ж структура, як у синхронному режимі).

### Параметри запиту `POST /analyze`

| Поле                       | Тип       | За замовч. | Опис                                                |
| -------------------------- | --------- | ---------- | --------------------------------------------------- |
| `file`                     | UploadFile | —         | `.eml`-файл (макс. 25 МБ)                           |
| `mode`                     | str       | `sync`     | `sync` або `async`                                  |
| `no_external`              | bool      | `false`    | Локальний режим — без DNS і VT                      |
| `enable_vt`                | bool      | `true`     | Дозволити VirusTotal (потребує ключ)                |
| `vt_api_key`               | str       | —          | Перевизначити `VT_API_KEY` з оточення               |
| `vt_upload_unknown_files`  | bool      | `false`    | Завантажувати на VT файли з невідомим хешем         |

### Приклад відповіді (скорочено)

```json
{
  "integrity": {
    "source_filename": "phishing.eml",
    "size_bytes": 2840,
    "md5": "284779c9...",
    "sha1": "a1b2c3...",
    "sha256": "2a4b3c...",
    "analyzed_at": "2026-05-04T11:30:00+00:00"
  },
  "settings": {
    "no_external": true,
    "dns_active": false,
    "vt_active": false
  },
  "metadata": {
    "from_address": "notify@amaz0n-delivery.tk",
    "from_display_name": "Amazon Shipping",
    "subject": "ALERT: Your package could not be delivered..."
  },
  "auth": {
    "spf":   { "status": "fail", "detail": "SPF FAILED..." },
    "dkim":  { "status": "fail", "detail": "DKIM signature verification FAILED..." },
    "dmarc": { "status": "fail", "detail": "DMARC FAILED..." }
  },
  "urls": [...],
  "attachments": [...],
  "scoring": {
    "risk_level": "Critical",
    "total_score": 76,
    "indicators": [...],
    "recommendations": [...]
  }
}
```

---

## Локальний (offline) режим

Прапорець `--no-external` (або псевдонім `--local-only`) повністю
відключає мережеві виклики:

- DNS-запити для пошуку SPF / DMARC TXT-записів пропускаються;
- запити до VirusTotal (URL та файлові хеші) пропускаються;
- залишаються всі евристичні перевірки на основі вмісту листа.

У такому режимі статуси SPF / DMARC, які потребують DNS, будуть
повертатися як `UNKNOWN` (а не `MISSING`), щоб уникнути штучного
завищення оцінки.

---

## Цілісність вихідного файлу

До початку парсингу обчислюються три криптографічні хеші байтів
вхідного `.eml`:

- **MD5** — швидкий, для сумісності з іншими інструментами;
- **SHA-1** — другий резервний хеш;
- **SHA-256** — основний канонічний хеш.

Хеші зберігаються у `IntegrityInfo` й включаються до:

- терміналового виведення CLI,
- титульної сторінки PDF-звіту,
- JSON-експорту,
- HTTP-відповіді API.

Це дозволяє довести, що звіт стосується саме того файлу, який було
проаналізовано (важливо для слідчих процедур та реагування на
інциденти).

---

## Логіка оцінювання ризику

Кожен індикатор має вагу `1–10`. Сума ваг формує загальний бал, який
мапиться у рівень ризику:

| Бал     | Рівень   |
| ------- | -------- |
| 0–9     | Low      |
| 10–19   | Medium   |
| 20–34   | High     |
| 35+     | Critical |

### Категорії індикаторів

| Категорія    | Приклади індикаторів                                              |
| ------------ | ----------------------------------------------------------------- |
| `auth`       | SPF Fail, DKIM Fail, DMARC Fail, DKIM Domain Mismatch             |
| `header`     | Reply-To Domain Mismatch, Display Name Spoofing, Suspicious Mailer |
| `url`        | IP-Based URL, Shortener, Suspicious TLD, Homograph, Anchor Mismatch, VT Malicious |
| `content`    | Urgency Language, Credential Harvesting Language                  |
| `attachment` | Suspicious Extension, Double Extension, VT Malicious / Suspicious |

---

## Структура проєкту

```
EmailAnalyzer/
├── analyzer/
│   ├── __init__.py          # Lazy public API (Settings, engine entries)
│   ├── settings.py          # Конфігурація (Settings dataclass)
│   ├── engine.py            # Орхестратор: analyze_email_file/bytes
│   ├── parser.py            # Парсер .eml у EmailData
│   ├── auth_checks.py       # SPF / DKIM / DMARC
│   ├── url_extractor.py     # Витягнення та евристика URL
│   ├── attachments.py       # Хеші + VT-перевірка вкладень
│   ├── threat_intel.py      # Клієнт VirusTotal v3 (URL + файли)
│   ├── indicators.py        # Зважена оцінка ризику
│   └── reporter.py          # PDF-звіт (ReportLab)
├── api/
│   ├── __init__.py
│   ├── main.py              # FastAPI-додаток (/health, /analyze)
│   └── schemas.py           # Pydantic-моделі публічного контракту
├── tests/
│   ├── samples/
│   │   ├── phishing.eml
│   │   ├── phishing_with_attachment.eml
│   │   ├── clean_email.eml
│   │   └── clean_with_attachment.eml
│   ├── test_parser.py
│   ├── test_auth_checks.py
│   ├── test_url_extractor.py
│   ├── test_indicators.py
│   └── test_attachments.py
├── main.py                  # CLI
├── requirements.txt
├── .env.example
└── README.md
```

---

## Тестування

```bash
# Усі тести
pytest

# Окремий модуль
pytest tests/test_parser.py -v

# Тільки тести аналізу вкладень
pytest tests/test_attachments.py -v

# З покриттям
pytest --cov=analyzer --cov-report=term-missing
```

Тестове покриття (102 тести) включає:

- парсинг `.eml` (фішинг + чистий лист);
- розбір заголовка `Authentication-Results`;
- витягування DKIM `d=` тегу;
- розбір DMARC-запису (policy + pct);
- евристики URL (IP / shortener / TLD / punycode / mismatch);
- зважене оцінювання ризику для фішингового та чистого листів;
- **аналіз вкладень**:
  - збереження байтів payload парсером;
  - обчислення MD5 / SHA-1 / SHA-256 (із детермінованими прекомп'ютеними
    значеннями для сталих зразків);
  - виявлення небезпечних розширень (`.exe`, `.docm` тощо);
  - виявлення подвійних розширень (`invoice.pdf.exe`);
  - відсутність хибних спрацьовувань на легітимних `.pdf` / `.png`
    вкладеннях;
  - наскрізна перевірка від `analyze_email_file` до `ScoringResult`
    (категорія `attachment` у `hits`).

### Тестові зразки

У [tests/samples/](tests/samples/) — чотири `.eml`-файли, що покривають
матрицю «фішинг ↔ чистий» × «з вкладеннями ↔ без вкладень»:

| Файл                             | Сценарій                                      | Очікуваний рівень |
| -------------------------------- | --------------------------------------------- | ----------------- |
| `phishing.eml`                   | Шахрайство «Amazon delivery» (без вкладень)   | Critical          |
| `phishing_with_attachment.eml`   | Фейковий рахунок із `invoice.pdf.exe` + `.docm` | Critical        |
| `clean_email.eml`                | Квитанція Stripe (без вкладень)               | Low               |
| `clean_with_attachment.eml`      | Робочий лист колеги з `.pdf` + `.png`         | Low               |

Симетрія «фішинг із вкладеннями ↔ чистий лист із вкладеннями» особливо
важлива: вона гарантує, що евристика виявляє шкідливі вкладення, але не
позначає кожен `.pdf` / `.png` як підозрілий.

---

## Ліцензія

Цей проєкт створено командою CyberCutlet в рамках курсу дисципліни "Командна робота". Усі права належать
автору.

## Автори

Дмитро Горбенко
Крижановський Кирило
Крижановська Анжеліка
