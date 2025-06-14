# ProxyGPT 🔒

**ProxyGPT** is an open-source monitoring proxy designed for **security engineers** in enterprise environments. It enables secure, auditable use of AI tools like ChatGPT while detecting and preventing potential data leaks through user conversations and file uploads.

Its allows enterprise users to access AI tools like ChatGPT while ensuring **visibility**, **data security**, and **compliance**. It enables organizations to benefit from AI productivity tools without sacrificing confidentiality or control over sensitive information.

> ⚠️ This is **not a privacy or anonymization tool** — ProxyGPT is built to **observe and control** AI tool usage across an organization.

---

## 🎯 Purpose

ProxyGPT helps organizations:
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
| **ProxyGPT UI**      | 443   | Secure web interface for monitoring (HTTPS)  |
|                      | 80    | Web interface (HTTP fallback)                |
| **Monitoring Proxy** | 8080  | MiTM proxy for AI traffic                    |

> Make sure client traffic to AI tools is routed through the proxy, e.g., via system proxy settings or PAC files.

---

## 🔒 Deployment Notes

- The proxy intercepts TLS traffic using a custom Root CA (`mitmCA.pem`)
- You must configure your client machines to trust this CA certificate
- The proxy inspects and decodes traffic from supported AI platforms
- All activity is logged and linked to the user or session that initiated it

---

## 👥 Target Audience

ProxyGPT is aimed at:
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
