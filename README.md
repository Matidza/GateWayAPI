
---

# Vyuzzes Gateway API

Welcome to the Gateway API for [Vyuzzes.com](https://vyuzzes.com), a SaaS platform designed to help students practice interviews with professionals. This API serves as the central gateway for managing authentication, user registration, and routing requests to appropriate services within the Vyuzzes ecosystem.

## 🚀 Features

* **User Authentication**: Secure login and registration functionalities.
* **Routing**: Directs API requests to the appropriate backend services.
* **Static File Serving**: Handles the delivery of static assets.
* **Database Integration**: Utilizes SQLite for data persistence.

## 🗂️ Project Structure

```
├── GateWayAPI/             # Core Django application
│   ├── __init__.py
│   ├── asgi.py
│   ├── settings.py         # Configuration settings
│   ├── urls.py             # URL routing
│   └── wsgi.py
├── LoginRegister/          # Handles user login and registration
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py           # Database models
│   ├── tests.py
│   ├── urls.py             # App-specific routes
│   └── views.py            # Request handlers
├── staticfiles/            # Static assets (CSS, JS, images)
├── db.sqlite3              # SQLite database file
├── manage.py               # Django's command-line utility
└── .gitignore
```

## 🛠️ Installation & Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Matidza/GateWayAPI.git
   cd GateWayAPI
   ```

2. **Create a Virtual Environment**:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:

   ```bash
   pip install django
   ```

4. **Apply Migrations**:

   ```bash
   python manage.py migrate
   ```

5. **Run the Development Server**:

   ```bash
   python manage.py runserver
   ```

   Access the application at `http://127.0.0.1:8000/`.

## 🧪 Testing

To run tests for the application:

```bash
python manage.py test
```

## 📄 API Endpoints

* `POST /register/`: Register a new user.
* `POST /login/`: Authenticate an existing user.
* Additional endpoints can be defined in `LoginRegister/urls.py` and handled in `LoginRegister/views.py`.

## 📚 Documentation

For detailed API documentation and usage examples, please refer to the [Vyuzzes API Documentation](https://vyuzzes.com/docs).

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

