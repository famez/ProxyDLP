# ProxyDLP 🔒

**ProxyDLP** is an open-source monitoring proxy designed for **security engineers** in enterprise environments. It enables secure, auditable use of AI tools like ChatGPT while detecting and preventing potential data leaks through user conversations and file uploads.

Its allows enterprise users to access AI tools like ChatGPT while ensuring **visibility**, **data security**, and **compliance**. It enables organizations to benefit from AI productivity tools without sacrificing confidentiality or control over sensitive information.

> ⚠️ This is **not a privacy or anonymization tool** — ProxyDLP is built to **observe and control** AI tool usage across an organization.

---

## Screenshots

<img width="1315" height="655" alt="Screenshot_2025-08-03_17-20-24" src="https://github.com/user-attachments/assets/475a6cd0-1a02-4179-8661-9d5bfe0b2d96" />
<img width="1314" height="654" alt="Screenshot_2025-08-03_17-20-58" src="https://github.com/user-attachments/assets/733bcb43-2300-4868-bd98-a79879bf9e23" />
<img width="1314" height="656" alt="Screenshot_2025-08-03_17-37-20" src="https://github.com/user-attachments/assets/5a0a7e2a-2b95-4736-bffa-c5f54b1a1ab9" />
<img width="1313" height="653" alt="Screenshot_2025-08-03_17-43-06" src="https://github.com/user-attachments/assets/7809b403-fd83-45bd-ad71-e27befbc2647" />
<img width="1313" height="657" alt="Screenshot_2025-08-03_17-48-15" src="https://github.com/user-attachments/assets/f0ee15d2-ef7f-46a5-83a9-398db9f1f1fb" />
<img width="1312" height="656" alt="Screenshot_2025-08-03_17-49-56" src="https://github.com/user-attachments/assets/25417d34-09e6-49be-bb4c-fe799052be1d" />
<img width="1312" height="657" alt="Screenshot_2025-08-03_17-50-21" src="https://github.com/user-attachments/assets/d9d9eb60-566a-4371-9065-3083bd7e5e3a" />
<img width="1314" height="657" alt="Screenshot_2025-08-03_17-51-03" src="https://github.com/user-attachments/assets/e6d384ae-f4b8-49b5-bae7-a05f1e3d07fb" />
<img width="1316" height="656" alt="Screenshot_2025-08-03_17-51-51" src="https://github.com/user-attachments/assets/3debc102-f508-40d6-9f19-f183108b2624" />
<img width="1317" height="657" alt="Screenshot_2025-08-03_17-53-14" src="https://github.com/user-attachments/assets/c65ef61c-0f71-40aa-87c6-6ed186b8dbbe" />
<img width="1313" height="657" alt="Screenshot_2025-08-03_17-53-46" src="https://github.com/user-attachments/assets/2dbbb55a-c0e9-4e8f-88c2-dba9c676fff1" />
<img width="1316" height="657" alt="Screenshot_2025-08-03_17-54-04" src="https://github.com/user-attachments/assets/138fccf0-8d05-42d6-8d90-d7000def4856" />
<img width="1314" height="656" alt="Screenshot_2025-08-03_18-01-16" src="https://github.com/user-attachments/assets/fec26d8e-02bc-4a3b-be4f-b687707c04ca" />
<img width="1313" height="656" alt="Screenshot_2025-08-03_18-04-56" src="https://github.com/user-attachments/assets/c0906789-e4c3-4d14-ac17-636ad528ed6d" />
<img width="1315" height="657" alt="Screenshot_2025-08-03_18-05-47" src="https://github.com/user-attachments/assets/a7ced2a4-99a3-464b-8def-c86c7440c50a" />
<img width="1318" height="657" alt="Screenshot_2025-08-03_18-06-37" src="https://github.com/user-attachments/assets/9850dbd8-6981-4282-9860-21cfd07d9f3a" />
<img width="1314" height="661" alt="Screenshot_2025-08-03_18-07-10" src="https://github.com/user-attachments/assets/b9075e97-af26-4fcb-a2c2-4288becff5a2" />
<img width="1314" height="658" alt="Screenshot_2025-08-03_18-17-53" src="https://github.com/user-attachments/assets/95eae3d1-6f74-41ee-a7b9-1c91a85b9778" />
<img width="1313" height="658" alt="Screenshot_2025-08-03_18-18-16" src="https://github.com/user-attachments/assets/48959051-f3e0-4a6b-8cd7-bbbae98f7789" />
<img width="1313" height="658" alt="Screenshot_2025-08-03_18-19-14" src="https://github.com/user-attachments/assets/17df4034-d94d-4d1c-bbe8-9d9ea13c7897" />
<img width="1315" height="658" alt="Screenshot_2025-08-03_18-20-43" src="https://github.com/user-attachments/assets/38fd21bb-5315-44e3-a2b0-b27bab316a4a" />
<img width="1316" height="657" alt="Screenshot_2025-08-03_18-22-43" src="https://github.com/user-attachments/assets/c5364777-d5b9-45ec-ae2e-cf8e6a2a723d" />


## 🎯 Purpose

ProxyDLP helps organizations:
- Monitor and inspect conversations with AI assistants
- Detect confidential or sensitive data in uploads and messages
- Link AI usage to individual users or accounts
- Provide a centralized interface for reviewing activity and enforcing policy

---

## ⚙️ Key Features

- **Proxy-based inspection** — AI-related traffic is routed through a local MiTM proxy (port `8080`)  
- **Conversation monitoring** — Intercept and inspect chat requests and responses  
- **File inspection** — Decode, extract, and analyze contents of uploaded PDFs, Excel files, and images (OCR)  
- **Pattern-based detection** — Configurable regular expressions detect potential data leaks  
- **Semantic topic matching** — Discover and match topics in conversations and files using Faiss vector indexes for efficient similarity search  
- **Dashboard interface** — Real-time view of events, traffic, and alerts for security engineers (available on HTTP `80` and HTTPS `443`)

---

## 🚀 Quickstart

### 🔧 Prerequisites

- Docker + docker-compose
- (Optional) Custom TLS/CA certificates

### 🧪 Setup Steps

```bash
# 1. Generate certificates and secrets
./generate_secrets.sh

# 2. Launch services
docker-compose up
```

### 🌐 Ports

| Component             | Port  | Description                                  |
|----------------------|-------|----------------------------------------------|
| **ProxyDLP UI**      | 443   | Secure web interface for monitoring (HTTPS)  |
|                      | 80    | Web interface (HTTP fallback)                |
| **Monitoring Proxy** | 8080  | MiTM proxy for AI traffic                    |

> Make sure client traffic to AI tools is routed through the proxy, e.g., via system proxy settings or PAC files.

---

## 🔒 Deployment Notes

- The proxy intercepts TLS traffic using a custom Root CA (`mitmCA.pem`)
- You must configure your client machines to trust this CA certificate (for example via GPO deployment).
- The proxy inspects and decodes traffic from supported AI platforms
- All activity is logged and linked to the user or session that initiated it
- Default user is admin and password is admin (can be changed after installation)
- It is recommended to configure a PAC file on the client machines (i.e. via GPO) so that only the traffic intended to the AI tools goes through the proxy, excluding the rest of the traffic. The PAC file can be automatically generated from the "SITES" page.

---

## 👥 Target Audience

ProxyDLP is aimed at:
- **Security engineers**
- **SOC analysts**
- **IT compliance teams**

It is intended for use inside organizations that wish to **embrace AI tools** without sacrificing **security oversight**.

---

## 🤝 Contributing

We welcome community contributions!

### 🛠️ How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Commit and push: `git commit -m "Add feature"` → `git push`
5. Open a Pull Request

> We recommend keeping PRs focused and writing meaningful commit messages.

### 🧪 Suggestions for Contribution

- Add support for more AI tools
- Improve PDF, Excel, and OCR parsing
- Enhance the dashboard UI/UX
- Add log filtering, alerting, or export options

---

## 🛡️ Reporting Vulnerabilities

If you discover a security vulnerability, please report it **privately**:

- Contact: f.amez1992@gmail.com
- Do not create public issues for security-related matters
- We follow responsible disclosure best practices

---
