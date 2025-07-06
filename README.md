# 🔎 Rafacon

**Rafacon** is a powerful recon tool inspired by `gau`, built for bug bounty hunters, CTF players, and red teamers. It collects historical URLs, filters out dead ones, checks for risky patterns, and even performs real-time CVE checks — all in one command.

---

## 🚀 Features

- 🌐 Collect URLs from Wayback Machine & Common Crawl  
- 🔁 Option to include subdomains  
- 🧹 Blacklist specific file types (e.g. `.png`, `.css`)  
- ✅ Filter and show only live URLs  
- ⚡ Multi-threaded live URL checking  
- 💾 Save results to a file  
- 🛡 Scan URLs for risky patterns (admin, login, config, etc.)  
- 📡 Perform real-time CVE lookups using public CVE APIs  
- 🎨 Cool ASCII banner on startup 😎  

---

## 📦 Installation

Make sure you have **Python 3** installed.

Install the required tools by running:

```bash
pip install requests waybackpy
```
That’s it — you’re ready to go!


# 🧠 Usage Examples

🔍 Basic recon
```
python rafacon.py example.com
```

