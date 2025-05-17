import os
import streamlit as st
import requests
from datetime import datetime, timedelta

# Настройки API
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8001")

def login(email: str, password: str):
    response = requests.post(
        f"{API_BASE_URL}/users/token",
        data={"username": email, "password": password}
    )
    response.raise_for_status()
    return response.json()

def register(email: str, password: str):
    response = requests.post(
        f"{API_BASE_URL}/users/",
        json={"email": email, "password": password}
    )
    return response.json()

def create_app(token: str, app_name: str, day_limit: int = 1000):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        f"{API_BASE_URL}/apps/",
        json={"app_name": app_name, "day_limit": day_limit},
        headers=headers
    )
    response.raise_for_status()
    return response.json()

def delete_app(token: str, app_token: str):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(
        f"{API_BASE_URL}/apps/",
        json={"app_token": app_token},
        headers=headers
    )
    return response.status_code == 200

def get_apps(token: str):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(
        f"{API_BASE_URL}/apps/all",
        headers=headers
    )
    response.raise_for_status()
    return response.json()

def check_url(api_key: str, url: str):
    response = requests.post(
        f"{API_BASE_URL}/urls/one",
        json={"url": url, "api_key": api_key}
    )
    response.raise_for_status()
    return response.json()

def check_urls_batch(api_key: str, urls: list):
    response = requests.post(
        f"{API_BASE_URL}/urls/list",
        json={"urls": urls, "api_key": api_key}
    )
    response.raise_for_status()
    return response.json()

def get_history(api_key: str, start_date: datetime = None, end_date: datetime = None):
    params = {"token": api_key}
    if start_date:
        params["start_dt"] = start_date.isoformat()
    if end_date:
        params["end_dt"] = end_date.isoformat()
    
    response = requests.post(
        f"{API_BASE_URL}/urls/history",
        json=params
    )
    response.raise_for_status()
    return response.json()

def main():
    st.set_page_config(page_title="Phishing Detection Service", layout="wide")
    
    if "token" not in st.session_state:
        st.session_state.token = None
        st.session_state.current_user = None
    
    # Авторизация
    with st.sidebar:
        st.title("🔐 Авторизация")
        
        auth_tab, reg_tab = st.tabs(["Вход", "Регистрация"])
        
        with auth_tab:
            email = st.text_input("Email", key="login_email")
            password = st.text_input("Пароль", type="password", key="login_pass")
            if st.button("Войти"):
                try:
                    token_data = login(email, password)
                    st.session_state.token = token_data["access_token"]
                    st.session_state.current_user = email
                    st.success("Успешный вход!")
                except Exception as e:
                    st.error("Ошибка входа. Проверьте email и пароль.")
        
        with reg_tab:
            new_email = st.text_input("Email", key="reg_email")
            new_password = st.text_input("Пароль", type="password", key="reg_pass")
            if st.button("Зарегистрироваться"):
                try:
                    register(new_email, new_password)
                    st.success("Регистрация успешна! Теперь вы можете войти.")
                except:
                    st.error("Ошибка регистрации. Возможно, email уже занят.")
        
        if st.session_state.token:
            if st.button("Выйти"):
                st.session_state.token = None
                st.session_state.current_user = None
                st.rerun()
    
    if not st.session_state.token:
        st.warning("Пожалуйста, войдите или зарегистрируйтесь для доступа к сервису")
        return
    
    # Основной интерфейс
    st.title("🛡️ Сервис проверки URL на фишинг")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Проверка URL", "Мои приложения", "История проверок", "API Документация"])
    
    with tab1:
        st.header("🔍 Проверить URL")
        col1, col2 = st.columns([3, 1])
        
        with col1:
            url = st.text_input("Введите URL для проверки", placeholder="https://example.com")
            
        with col2:
            api_key = st.text_input("API ключ", help="Получите API ключ во вкладке 'Мои приложения'")
        
        if st.button("Проверить") and url:
            if not api_key:
                st.warning("Пожалуйста, укажите API ключ")
            else:
                try:
                    result = check_url(api_key, url)
                    if result.get("is_phishing"):
                        st.error(f"⚠️ Фишинговый URL! Уверенность: {result['confidence_level']*100:.1f}%")
                        st.write(f"Причина: {result['reason']}")
                    else:
                        st.success(f"✅ Безопасный URL. Уверенность: {100 - result['confidence_level']*100:.1f}%")
                except Exception as e:
                    st.error(f"Ошибка при проверке URL: {str(e)}")
        
        st.divider()
        st.header("📦 Пакетная проверка")
        urls_text = st.text_area("Введите URL для пакетной проверки (по одному на строку)", height=100)
        if st.button("Проверить пакетно") and urls_text:
            if not api_key:
                st.warning("Пожалуйста, укажите API ключ")
            else:
                urls = [url.strip() for url in urls_text.split("\n") if url.strip()]
                try:
                    results = check_urls_batch(api_key, urls)
                    for url, result in zip(urls, results):
                        with st.expander(f"Результат для {url}"):
                            if result.get("is_phishing"):
                                st.error(f"⚠️ Фишинговый URL! Уверенность: {result['confidence_level']*100:.1f}%")
                                st.write(f"Причина: {result['reason']}")
                            else:
                                st.success(f"✅ Безопасный URL. Уверенность: {result['confidence_level']*100:.1f}%")
                except Exception as e:
                    st.error(f"Ошибка при пакетной проверке: {str(e)}")
    
    with tab2:
        st.header("📱 Мои приложения")
        
        try:
            apps = get_apps(st.session_state.token)
            
            if not apps:
                st.info("У вас пока нет приложений. Создайте первое приложение ниже.")
            else:
                for app in apps:
                    with st.expander(f"🔑 {app['app_name']}"):
                        st.code(f"API ключ: {app['token']}", language="text")
                        st.write(f"Лимит проверок в день: {app['day_limit']}")
                        st.write(f"Использовано сегодня: {app['url_count_on_day']}")
                        
                        if st.button(f"Удалить {app['app_name']}", key=f"del_{app['token']}"):
                            try:
                                if delete_app(st.session_state.token, app['token']):
                                    st.success("Приложение удалено!")
                                    st.rerun()
                            except Exception as e:
                                st.error(f"Ошибка при удалении: {str(e)}")
        
        except Exception as e:
            st.error(f"Ошибка при получении списка приложений: {str(e)}")
        
        st.divider()
        st.header("➕ Создать новое приложение")
        
        with st.form("create_app"):
            app_name = st.text_input("Название приложения", placeholder="Мое приложение")
            day_limit = st.number_input("Дневной лимит проверок", min_value=1, value=1000)
            
            if st.form_submit_button("Создать"):
                try:
                    result = create_app(st.session_state.token, app_name, day_limit)
                    st.success(f"Приложение создано! API ключ: {result['token']}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Ошибка при создании приложения: {str(e)}")
    
    with tab3:
        st.header("📊 История проверок")
        
        api_key = st.text_input("API ключ для истории", help="Введите API ключ приложения", key="history_api_key")
        
        if api_key:
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input("Начальная дата", value=datetime.now() - timedelta(days=7))
            with col2:
                end_date = st.date_input("Конечная дата", value=datetime.now())
            
            if st.button("Загрузить историю"):
                try:
                    history = get_history(
                        api_key,
                        datetime.combine(start_date, datetime.min.time()),
                        datetime.combine(end_date, datetime.max.time())
                    )
                    
                    st.subheader(f"📌 {history['app_name']}")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Всего проверок", history['all_urls'])
                    with col2:
                        st.metric("Фишинговых URL", history['phishing_urls'])
                    with col3:
                        st.metric("Осталось проверок", history['day_limit_remaining'])
                    
                    st.divider()
                    
                    if history['history_urls']:
                        st.subheader("Последние проверки")
                        for url, result, ts in zip(
                            history['history_urls'],
                            history['history_results'],
                            history['history_ts']
                        ):
                            with st.expander(f"{ts} - {url[:50]}..."):
                                if result['is_phishing']:
                                    st.error(f"⚠️ Фишинг ({result['confidence_level']*100:.1f}%)")
                                else:
                                    st.success(f"✅ Безопасно ({result['confidence_level']*100:.1f}%)")
                                st.write(f"Причина: {result['reason']}")
                    else:
                        st.info("Нет данных за выбранный период")
                
                except Exception as e:
                    st.error(f"Ошибка при загрузке истории: {str(e)}")
    
    with tab4:
        st.header("📚 API Документация")
        
        st.markdown("""
        ### Базовый URL
        ```
        {API_BASE_URL}
        ```
        
        ### Аутентификация
        Получите токен доступа:
        ```http
        POST /users/token
        Content-Type: application/x-www-form-urlencoded
        
        username=your_email@example.com&password=your_password
        ```
        
        ### Управление приложениями
        - **Создать приложение**:
        ```http
        POST /apps/
        Authorization: Bearer <your_token>
        Content-Type: application/json
        
        {"app_name": "My App", "day_limit": 1000}
        ```
        
        - **Получить список приложений**:
        ```http
        GET /apps/all
        Authorization: Bearer <your_token>
        ```
        
        - **Удалить приложение**:
        ```http
        DELETE /apps/
        Authorization: Bearer <your_token>
        Content-Type: application/json
        
        {"app_token": "your_app_token"}
        ```
        
        ### Проверка URL
        - **Проверить один URL**:
        ```http
        POST /urls/one
        Content-Type: application/json
        
        {"url": "https://example.com", "api_key": "your_app_token"}
        ```
        
        - **Пакетная проверка** (до 10 URL):
        ```http
        POST /urls/list
        Content-Type: application/json
        
        {"urls": ["https://example.com", "https://test.com"], "api_key": "your_app_token"}
        ```
        
        - **Получить историю проверок**:
        ```http
        POST /urls/history
        Content-Type: application/json
        
        {"token": "your_app_token", "start_dt": "2023-01-01", "end_dt": "2023-01-31"}
        ```
        """)

if __name__ == "__main__":
    main()