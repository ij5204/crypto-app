# 🔐 Crypto-App

A full-stack encryption and decryption web application built with **Rust**, **React (Vite)**, and **Supabase**.  
The app lets users securely encrypt/decrypt text or files using multiple algorithms, manage saved keys, and view encrypted data through a clean Material-UI interface.

---

## 🚀 Tech Stack

### 🧠 Frontend
- **React + Vite** — fast build system and modern UI setup  
- **Material-UI (MUI)** — polished, responsive components  
- **Axios / Fetch API** — communicate with backend  
- **Vite Environment Variables (.env)** — manage API endpoints securely  

### ⚙️ Backend
- **Rust (Actix-Web / Axum)** — high-performance web server  
- **PostgreSQL (via Supabase)** — persistent storage for users and encrypted data  
- **dotenv / envy** — configuration management  
- **serde / tokio** — async JSON serialization and handling  

---

## 🧩 Features

- 🔑 **Encrypt / Decrypt text or files** using AES, RSA, or custom algorithms  
- 📦 **Store encrypted content** securely in Supabase  
- 🧾 **View encryption history** (timestamp, algorithm used)  
- 🧍‍♂️ **User Authentication** via Supabase Auth  
- 🧮 **Key management** (generate, reuse, or import custom keys)  
- 🌗 **Dark / Light Mode** toggle  
- ⚡ **Rust backend APIs** for high-speed cryptographic operations  

---

## Example API Request

- 🔑 Encrypt a message
curl -X POST http://localhost:4089/encrypt \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"AES","plaintext":"Hello Ishaa"}'

## 👩‍💻 Author

Ishaa Jain \
University of Cincinnati · Computer Science \
LinkedIn • GitHub




