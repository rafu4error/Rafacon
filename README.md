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

🌐 Include subdomains
```
python rafacon.py example.com --subs
```
🚫 Exclude file types
```
python rafacon.py example.com --blacklist png,jpg
```
✅ Show only live URLs
```
python rafacon.py example.com --live
```
🛡 Risky path check
```
python rafacon.py example.com --cve
```
📡 Real-time CVE lookup
```
python rafacon.py example.com --realtime-cve
```
💾 Save to file
```
python rafacon.py example.com --o result.txt
```
🎯 Full power
```
python rafacon.py example.com --subs --live --cve --realtime-cve --blacklist jpg,png --threads 20 -
```

## 🔐 Why Use Rafacon?
Rafacon helps you:

#### 🚀 Quickly collect and clean URLs for recon

#### 🔍 Focus on live, working endpoints

#### 🛡 Identify risky or exposed paths

#### 📡 Discover real-time CVEs based on URL content

# Built By RAFU(walwa)
Inspired by gau, made smarter for serious hunters.
