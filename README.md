# Механизм анализа логов

Проект для анализа серверных логов (Apache/Nginx) с использованием Pandas для выявления попыток взлома и аномалий трафика.

## Возможности

### Анализ безопасности
- **SQL-инъекции**: обнаружение попыток внедрения SQL-кода
- **XSS-атаки**: выявление межсайтовых скриптов
- **Path Traversal**: обнаружение попыток доступа к файловой системе
- **Command Injection**: выявление инъекций команд
- **Brute Force**: обнаружение атак подбора паролей
- **Сканирование**: выявление сканирования уязвимостей
- **Доступ к админ-панелям**: мониторинг попыток доступа к административным ресурсам

### Анализ трафика
- **Всплески трафика**: обнаружение аномальных пиков запросов
- **DDoS-атаки**: выявление потенциальных атак отказа в обслуживании
- **Бот-трафик**: определение автоматизированного трафика
- **Анализ паттернов**: почасовые и дневные паттерны трафика
- **Статус-коды**: распределение HTTP-кодов ответов

### Визуализация
- График временной шкалы трафика
- Распределение HTTP-статус кодов
- Почасовые паттерны трафика
- Топ IP-адресов
- График обнаруженных атак
- Комплексная дашборд

## Установка

1. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd log_analyzer
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

## Использование

### Базовый анализ
```bash
python main.py -f /path/to/access.log
```

### Анализ логов Nginx
```bash
python main.py -f /path/to/nginx.log --format nginx
```

### Анализ с сохранением в указанную директорию
```bash
python main.py -f /path/to/access.log -o results
```

### Только краткая сводка
```bash
python main.py -f /path/to/access.log --summary-only
```

## Структура проекта

```
log_analyzer/
├── src/
│   ├── log_parser.py          # Парсер логов Apache/Nginx
│   ├── security_analyzer.py   # Анализ безопасности
│   ├── traffic_analyzer.py    # Анализ трафика
│   └── visualizer.py          # Визуализация результатов
├── examples/
│   ├── sample_apache.log      # Пример логов Apache
│   └── sample_nginx.log       # Пример логов Nginx
├── output/                    # Директория для результатов
├── main.py                    # Основной скрипт
└── requirements.txt          # Зависимости
```

## Пример использования

### Анализ тестовых данных
```bash
# Анализ Apache логов
python main.py -f examples/sample_apache.log

# Анализ Nginx логов
python main.py -f examples/sample_nginx.log --format nginx
```

### Результаты анализа

После выполнения анализа создаются:
- **JSON отчет**: детальный отчет с результатами анализа
- **Графики**: визуализация паттернов и аномалий
- **Сводка**: краткая информация в консоли

## Форматы логов

### Apache Common Log Format
```
192.168.1.100 - - [25/Jan/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

### Nginx Log Format
```
192.168.1.100 - - [25/Jan/2026:15:30:01 +0300] "GET / HTTP/1.1" 200 1234 "https://google.com" "Mozilla/5.0"
```

## Метрики безопасности

Система вычисляет следующие метрики:
- **Risk Score**: оценка риска для IP-адресов (0-100)
- **Error Rate**: процент ошибок для каждого IP
- **Attack Severity**: серьезность обнаруженных атак
- **Traffic Anomalies**: аномалии трафика

## Требования

- Python 3.7+
- Pandas >= 1.5.0
- NumPy >= 1.21.0
- Matplotlib >= 3.5.0
- Seaborn >= 0.11.0
- Scipy >= 1.9.0

## Пример вывода

```
[*] Parsing log file: examples/sample_apache.log
[+] Successfully parsed 25 log entries
[+] Time range: 2026-01-25 10:00:01 to 2026-01-25 10:00:26
[+] Unique IPs: 12

[*] Analyzing security threats...
[*] Analyzing traffic patterns...
[+] Report saved to: output/analysis_report_1643123456.json

==================================================
ANALYSIS SUMMARY
==================================================

Security Threats Detected:
  SQL Injection attempts: 2
  XSS attempts: 2
  Path traversal attempts: 2
  Command injection attempts: 2
  Brute force attacks: 1
  Scanning activities: 0
  Admin access attempts: 2

Traffic Anomalies:
  Traffic spikes: 0
  Potential DDoS patterns: 0

Traffic Statistics:
  Total requests: 25
  Unique IPs: 12
  Bot IPs detected: 3
```

## Лицензия

MIT License