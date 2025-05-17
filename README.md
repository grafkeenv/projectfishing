# Сервис проверки URL на фишинг

Этот сервис предоставляет API для проверки URL-адресов на фишинг с использованием черных списков и модели машинного обучения.

## Основные эндпоинты

### Проверка одного URL

**POST /urls/one**

**Параметры запроса (JSON):**

* `url`: URL-адрес для проверки (строка).
* `api_key`: API ключ приложения (строка).

**Ответ (JSON):**

* `is_phishing`: `true`, если URL-адрес считается фишинговым, иначе `false` (логическое значение).
* `confidence_level`: Уровень достоверности результата (число с плавающей точкой от 0 до 1).
* `reason`: Причина, по которой URL-адрес был классифицирован как фишинговый (строка).

**Пример запроса:**

```bash
curl -X POST -H "Content-Type: application/json" -d '{"url": "https://example.com", "api_key": "YOUR_API_KEY"}' http://localhost:8001/urls/one
```

### Проверка списка URL

**POST /urls/list**

**Параметры запроса (JSON):**

* `urls`: Список URL-адресов для проверки (массив строк).
* `api_key`: API ключ приложения (строка).


**Ответ (JSON):**

Массив объектов, каждый из которых имеет структуру, аналогичную ответу `/urls/one`.

**Пример запроса:**

```bash
curl -X POST -H "Content-Type: application/json" -d '{"urls": ["https://example.com", "https://google.com"], "api_key": "YOUR_API_KEY"}' http://localhost:8001/urls/list
```

### Управление пользователями

**POST /users/** - регистрация нового пользователя. Принимает JSON с полями `email` и `password`.

**POST /users/token** - получение токена авторизации. Принимает параметры `username` (email) и `password` в формате x-www-form-urlencoded.

**GET /users/me** - информация о текущем пользователе. Требует авторизации (Bearer token).


### Управление приложениями

**POST /apps/** - создание нового приложения.  Принимает JSON с полем `app_name`.  Возвращает API ключ (`token`). Требует авторизации.

**GET /apps/all** -  получение списка приложений пользователя. Требует авторизации.

**PUT /apps/** - изменение имени приложения. Принимает JSON с полями `app_token` и `new_name`. Требует авторизации.

**DELETE /apps/** - удаление приложения. Принимает JSON с полем `app_token`. Требует авторизации.


### История проверок (для приложения)

**POST /urls/history**

**Параметры запроса (JSON):**

* `token`: API ключ приложения (строка).
* `start_dt`: Начало периода (опционально, формат ISO 8601).
* `end_dt`: Конец периода (опционально, формат ISO 8601).

**Ответ (JSON):**

* `app_name`: Имя приложения.
* `all_urls`: Общее количество проверенных URL.
* `phishing_urls`: Количество фишинговых URL.
* `day_limit`: Дневной лимит проверок.
* `day_limit_remaining`: Остаток дневного лимита.
* `history_urls`: Список проверенных URL.
* `history_results`: Список результатов проверок (аналогично ответам `/urls/one`).
* `history_ts`: Список временных меток проверок.


## Запуск

Сервис запускается с помощью Docker Compose:

```bash
docker-compose up -d

## Тесты

Интегрированы в Docker Compose.

- Юнит-тесты

```bash
# С покрытием кода
docker-compose run tests sh -c "coverage run -m pytest tests/unit/ -v && coverage report -m"

# Без покрытия
docker-compose run tests sh -c "pytest tests/unit/ -v"
```

- Функциональные тесты:

```bash
# С покрытием кода
docker-compose run tests sh -c "coverage run -m pytest tests/integration/ -v && coverage report -m"

# Без покрытия
docker-compose run tests sh -c "pytest tests/integration/ -v"
```

- Нагрузочные тесты

```bash
docker-compose up locust
```

## Клиент streamlit

Доступен в сборке docker-compose (порт: 8501).
