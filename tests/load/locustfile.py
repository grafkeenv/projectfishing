from locust import HttpUser, task, between
from datetime import datetime, timedelta
import random
import string

class PhishingDetectionUser(HttpUser):
    wait_time = between(1, 5)
    host = "http://localhost:8001"
    
    # Общие тестовые данные для всех пользователей
    test_apps = []
    test_urls = [
        "http://legit-site.com",
        "http://phishing-site.com",
        "http://bank-site.com/login",
        "http://scam-site.net/promo",
        "http://trusted-site.org"
    ]
    
    def on_start(self):
        """Выполняется при старте каждого виртуального пользователя"""
        email = f"user{random.randint(1, 1000000)}@test.com"
        password = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        
        self.client.post("/users/", json={
            "email": email,
            "password": password
        })
        
        response = self.client.post("/users/token", data={
            "username": email,
            "password": password
        })
        self.token = response.json()["access_token"]
        
        if not PhishingDetectionUser.test_apps:
            app_name = f"TestApp-{random.randint(1, 100)}"
            response = self.client.post(
                "/apps/",
                json={"app_name": app_name},
                headers={"Authorization": f"Bearer {self.token}"}
            )
            PhishingDetectionUser.test_apps.append(response.json()["token"])
        
        self.api_key = random.choice(PhishingDetectionUser.test_apps)
    
    @task(5)
    def check_single_url(self):
        """Проверка одного URL"""
        url = random.choice(self.test_urls)
        self.client.post(
            "/urls/one",
            json={
                "url": url,
                "api_key": self.api_key
            },
            name="/urls/one"
        )
    
    @task(2)
    def check_batch_urls(self):
        """Пакетная проверка URL (2-5 URL за запрос)"""
        num_urls = random.randint(2, 5)
        urls = random.choices(self.test_urls, k=num_urls)
        
        self.client.post(
            "/urls/list",
            json={
                "urls": urls,
                "api_key": self.api_key
            },
            name="/urls/list"
        )
    
    @task(1)
    def get_app_history(self):
        """Получение истории проверок для приложения"""
        if self.api_key:
            days_back = random.randint(1, 30)
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            self.client.post(
                "/urls/history",
                json={
                    "token": self.api_key,
                    "start_dt": start_date.isoformat(),
                    "end_dt": end_date.isoformat()
                },
                name="/urls/history"
            )
    
    @task(1)
    def manage_applications(self):
        """Управление приложениями (создание/получение списка)"""
        if random.random() < 0.3:
            app_name = f"App-{random.randint(1, 1000)}"
            response = self.client.post(
                "/apps/",
                json={"app_name": app_name},
                headers={"Authorization": f"Bearer {self.token}"}
            )
            new_app_token = response.json()["token"]
            PhishingDetectionUser.test_apps.append(new_app_token)
        
        self.client.get(
            "/apps/all",
            headers={"Authorization": f"Bearer {self.token}"},
            name="/apps/all"
        )