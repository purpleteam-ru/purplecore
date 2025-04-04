# purplecore
Программа для автоматического поиска уязвимостей в исходном коде (PHP, Java, Python, JS) с использованием AI и пользовательских правил

## Особенности
- 🛡️ Поиск 50+ типов уязвимостей (SQLi, XSS, RCE и др.)
- 🤖 Интеграция с моделями DeepSeek и CodeBERT
- 📂 Рекурсивное сканирование директорий
- 📊 Генерация обучающего датасета
- 🎚️ Интерактивный режим проверки

## Установка
```bash
pip install transformers torch pyyaml
git clone [https://github.com/purpleteam-ru/purplecore]
cd purplecore
```
### Использование 

Сканирование проекта

python analyzer.py /path/to/project

Интерактивная проверка

python analyzer.py --review

### Конфигурация

Создайте scanner_config.yaml:

```yaml
exclude_dirs: ['.git', 'node_modules']
model: deepseek-ai/DeepSeek-R1
rules:
  - security.yaml
  - custom_rules.yaml
```

### Примерные результаты

    SQL Injection:

        Код: stmt.execute("SELECT * FROM users WHERE id = " + request.getParameter("id"))

        Уровень риска: 🔴 Высокий (0.95)

    Log Forging:

        Код: logger.info("User action: " + userInput)

        Уровень риска: 🟠 Средний (0.75)

    Path Traversal:

        Код: FileUtils.readFile(request.getParameter("file"))

        Уровень риска: 🟡 Низкий (0.65)
