# 🛡️ Safe Space Web Filter Proxy

A simple educational web filtering proxy built in Python.  
It can **block specific domains or keywords** in HTTP/HTTPS traffic and show a custom HTML message —  
> “Go do some work, you lazybones!”

---

## 🚀 Features
- Works as a local **HTTP/HTTPS proxy**
- **Blocklist mode:** blocks only the listed domains or keywords  
- Shows a custom **403 HTML page** for blocked sites
- Logs all decisions in `decisions.log`
- `/status` endpoint with JSON stats
- Supports **HTTPS tunneling (CONNECT)** and MITM for blocked hosts

---

## ⚙️ Setup

1. **Install dependencies**
 
   pip install pyopenssl certifi
Run the proxy

python3 web_filter_proxy.py
You’ll see:

Web filter listening on 0.0.0.0:8888
[MODE] Blocklist mode, default_policy=allow
[ADMIN] Status available at http://127.0.0.1:8890/status
Configure your browser to use the proxy

HTTP Proxy: 127.0.0.1

Port: 8888

Also use it for HTTPS

Import and trust the certificate

File: ca.cert.pem

Add it to your browser’s trusted certificates (for MITM HTTPS pages)

🧱 Configuration
Edit config.json:
{
  "listen_host": "0.0.0.0",
  "listen_port": 8888,
  "allow_hosts": [],
  "block_hosts": [
    "facebook.com", ".facebook.com",
    "instagram.com", ".instagram.com",
    "tiktok.com", ".tiktok.com"
  ],
  "block_url_keywords": ["secret", "forbidden"],
  "default_policy": "allow",
  "admin_host": "127.0.0.1",
  "admin_port": 8890
}
Empty allow_hosts → works in blocklist mode

Add hosts to block_hosts to block them

You can view live stats at http://127.0.0.1:8890/status

🪵 Logs
All filtering decisions are stored in:

decisions.log
View live logs:

tail -f decisions.log
⚠️ Notes
MITM decryption works only for blocked HTTPS hosts (to show HTML 403 page)

Do not use this proxy on real networks — it’s for educational purposes only

Keep ca.key.pem private

Author: Bogdan Orel
Project: Safe Space (Cybersteps)