<p align="center">
  🇬🇧 <a href="README.md">English</a> &nbsp;|&nbsp;
  🇮🇷 <a href="README.fa.md">فارسی</a>
</p>

<div align="center">
 
# ⚡ ZEUS PANEL
[![Version](https://img.shields.io/badge/Version-v2.0.6-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/zeus-panel/ZEUS-PANEL)
[![Platform](https://img.shields.io/badge/Platform-Cloudflare%20Workers-f38020.svg?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License](https://img.shields.io/badge/License-Proprietary%20(Non--Commercial)-red.svg?style=for-the-badge)](https://github.com/zeus-panel/ZEUS-PANEL/blob/main/LICENSE)
[![Telegram](https://img.shields.io/badge/Community-PANEL__ZEUS-2CA5E0.svg?style=for-the-badge&logo=telegram)](https://t.me/PANEL_ZEUS)
</div>

<table width="100%">
<tr>
<td width="50%" valign="middle" align="center">
<img src="https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/photos/dark.png" width="100%" alt="Zeus Panel Dark Mode" style="border-radius: 12px;">
</td>
<td width="50%" valign="middle" align="center">
<img src="https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/photos/1.png" width="100%" alt="Zeus Panel Screenshot 1" style="border-radius: 12px;">
</td>
</tr>
<tr>
<td width="50%" valign="middle" align="center">
<img src="https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/photos/2.png" width="100%" alt="Zeus Panel Screenshot 2" style="border-radius: 12px;">
</td>
<td width="50%" valign="middle" align="center">
<img src="https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/photos/3.png" width="100%" alt="Zeus Panel Screenshot 3" style="border-radius: 12px;">
</td>
</tr>
</table>
 
<table width="100%">
<tr>
<td width="50%" valign="middle" align="center">
<img src="https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/photos/bot.png" width="100%" alt="Zeus Panel Status" style="border-radius: 12px;">
</td>
<td width="50%" valign="middle" align="center">
<img src="https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/photos/status.png" width="100%" alt="Zeus Panel Dark Mode" style="border-radius: 12px;">
</td>
</tr>
</table>

<div align="center">

[⚡️ Key Features](#features) • [🚀 Deployment Guide](#-quick-deployment-guide) • [🔎 IP Scanner](#-clean-ip-scanner) • [🛡️ SOCKS5 Proxy](#️-build-your-own-socks5-proxy-zeus-relay) • [❤️ Donate](#-donate--support) • [⚖️ License & Copyright](#license-copyright) • [Credits](#credits-section)
</div>


> [!CAUTION]
> **Security Notice**
> If you believe this project does not comply with GitHub's Community Guidelines or Acceptable Use Policies, please let us know. We make every effort to ensure all our projects are secure and compliant with GitHub's policies.

---


## <a id="features"></a>⚡️ Features & Capabilities

**🚀 Core Protocols & Routing**
* 📡 Dual Protocol Support: Native, highly optimized support for both VLESS and Trojan protocols over WebSocket, allowing simultaneous multi-protocol config generation.
* 🌍 Multi-Location Routing (Up to 8 Proxies): Seamlessly assign up to 8 distinct proxies or geographic locations simultaneously to individual users.
* 🔀 Automated Proxy Fallback: Intelligent auto-replacement of failing upstream user proxies with healthy nodes dynamically fetched from dedicated VIP proxy repositories.
* 🌐 Dynamic IP Rotation: Automated rotation of Clean Cloudflare Edge IPs at custom, user-defined intervals (e.g., every 5 minutes).

**🛡 Advanced Anti-Filtering & DPI Bypass**
* 🧩 Advanced TLS Fragmentation: Built-in TLS Fragment support (length and interval) to bypass deep packet inspection (DPI).
* 🇮🇷 ISP-Specific Presets: One-click optimized fragmentation presets for specific network operators (MCI, Irancell, Rightel, TCI, and Gaming mode).
* 🎭 Patterniha (PattN/PattNG) Integration: Native support for advanced JSON fragmentation (fm), Custom Cipher Suites (cs), and TLS Masking (Custom SNI/Host) for ultimate stealth.
* 🕵️ ClientHello Fingerprint Simulator: Dynamically spoof browser fingerprints (Chrome, Safari, iOS, Android, Edge, Randomized, Unsafe) to evade censorship.

**👥 Advanced User Management & Billing**
* ⚖️ Strict Quota Enforcement: Set precise limits based on Traffic Volume (GB), Time Expiration (Days), Total Requests, and Concurrent Devices (IP Limit).
* ⏳ Start on First Connect: Option to delay the countdown of a user's subscription time until their very first successful connection.
* ♻️ Automated Quota Resets: Scheduled auto-reset capabilities for volume and request counters based on user-specific timeframes.
* 🛠 Bulk Operations: Comprehensive multi-select tools for batch user status toggling, deletion, and quota/time resets.

**🛑 Security & Content Control**
* 🚫 Smart Content Blocker: Integrated DNS-over-HTTPS (DoH) engine to actively intercept and block NSFW (Porn) content and advertisements per user.
* 🔐 Panel Auth Protection: Secure SHA-256 hashed panel password with built-in brute-force protection mechanisms (temporary bans after failed login attempts).
* 🔏 Anti-Tamper & DRM: Mathematically entangled core and integrity checks to prevent code manipulation and unauthorized white-labeling.

**📱 UI/UX & Ecosystem**
* 📲 Progressive Web App (PWA): Fully installable on iOS, Android, and Desktop as a standalone application for a native app-like experience.
* 🌙 Modern AMOLED UI: A responsive, mobile-friendly interface built with Tailwind CSS, featuring full AMOLED Dark Mode, smooth 3D background waves (Three.js), and interactive UI elements.
* 🔗 Self-Service Portals: Auto-generation of robust Subscription Links, QR codes, and dedicated real-time status pages for every user.

**🛠 Built-in Diagnostic & Automation Tools**
* 🔍 Built-in Scanners: Integrated Clean IP Scanner (with Pydroid & CMD copy-paste scripts) and VIP Proxy Scanner directly inside the panel.
* 📡 Live Ping & Direct Test: In-panel utility to test direct ping from the user to Cloudflare, and from Cloudflare to the global internet.
* 📊 Live CF Quota Monitoring: Real-time tracking of Cloudflare Worker requests (Total and Daily) with visual progress bars to proactively prevent account 100k limit bans.
* 🔄 OTA Core Updates: Automated edge deployment system updating the panel directly from the official repository without database or data loss.
* 🗄 Complete Backup System: Full JSON export and import utility covering the entire D1 database, users, and server configuration state.

**🤖 Automation & Deployment**
* 🚀 One-Click Deployment: Complete provisioning of the panel, subdomain, and D1 database directly via the Telegram Bot.
* 👥 Multi-Account Bot Management: Simultaneously manage multiple Cloudflare accounts, execute panel updates, and recover passwords securely.
* ☁️ Cloudflare Ecosystem Optimized: Architected strictly within Cloudflare limits, utilizing intelligent D1 connection pooling and Queue batching mechanisms for maximum operational efficiency.


---

# 🚀 Quick Deployment Guide

<div align="center">

<a href="https://dash.cloudflare.com/" target="_blank">
<img src="https://img.shields.io/badge/Cloudflare_Dashboard-Login-f38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Cloudflare Dashboard" height="40">
</a>

<div align="center">
First, log into your Cloudflare dashboard. Ensure you are using a verified email address, then proceed with the deployment method below.
</div>

<br>

<a href="https://t.me/ZEUS_PANEL_BOT" target="_blank">
<img src="https://img.shields.io/badge/Zeus_Telegram_Bot-Start_Bot-0088cc?style=for-the-badge&logo=telegram&logoColor=white" alt="Zeus Telegram Bot" height="40">
</a>

</div>

<br>

## 🤖  Deploy via Telegram Bot 

1. 🌐 Access the **[ZEUS Telegram Bot](https://t.me/ZEUS_PANEL_BOT)** and click `Start`.
2. 👤 From the main menu, click on **"➕ Register Cloudflare Account"**.
3. 🔗 Click the inline button **"🔑 Get Cloudflare Token"** to be redirected to your Cloudflare account.
4. 🟦 Scroll to the bottom of the Cloudflare page, click the blue `Continue to summary` button, and then click `Create Token`.
5. 🔑 Copy the generated token and **send it directly in the bot chat**.
6. ⚡️ Once the token is verified, return to the main menu, click **"🚀 Build New Panel"**, and select your account. Your D1 database and panel will be automatically deployed.

---

> [!CAUTION]
> **CRITICAL SECURITY NOTE:** Ensure you securely save the initial administrative password you set during your first login to the panel. Do not lose it!

---


# 🛡️ Build Your Own SOCKS5 Proxy (Zeus Relay)

A dedicated bash script is provided to instantly deploy a private, secure SOCKS5 proxy on any Linux VPS (Ubuntu, Debian, CentOS, Rocky Linux). This is highly recommended for users who wish to create VIP residential proxies to route traffic through clean, dedicated IPs.

To install, update, or remove the Dante SOCKS5 proxy, execute the following command on your Linux server with root privileges:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/main/zeus-relay.sh | sed 's/\r$//')
```

The script features an interactive menu, automatic port configuration, random secure credential generation (username/password), and native IPv4/IPv6 integration.

---

# 🔎 Clean IP Scanner

ZEUS Panel features a highly optimized, multi-threaded local IP scanner. You can quickly find the fastest and most stable clean Cloudflare IPs directly from your device using the methods below:

### 📱 Mobile Users (Pydroid 3 - Android)
1. Install **[Pydroid 3](https://play.google.com/store/apps/details?id=ru.iiec.pydroid3)** from the Google Play Store.
2. Open the app, navigate to the **Terminal** from the side menu, and execute the following command:

```bash
python -c "import urllib.request; req = urllib.request.Request('https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/zeus-scanner.txt', headers={'User-Agent': 'Mozilla/5.0'}); exec(urllib.request.urlopen(req).read().decode('utf-8').split('---PYTH' + 'ON---')[1].split('---POWERSHELL---')[0].strip())"

```

3. Once the server initializes, open `http://127.0.0.1:8000` in your web browser.

### 💻 Windows Users (CMD / PowerShell)

Open **Command Prompt (CMD)** in Windows, paste the following command, and hit Enter. The high-speed scanner interface will automatically compile and launch:

```cmd
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13; $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $text = ($wc.DownloadString('https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/zeus-scanner.txt') -split '---POWERSHELL---')[1].Trim(); [IO.File]::WriteAllText('zeus-scanner.ps1', $text, [System.Text.Encoding]::UTF8); .\zeus-scanner.ps1"

```

---


# 💰 Donate & Support

<p align="center">Built with ❤️</p>

<p align="center"><a href="https://donatonion.ir-netlify.workers.dev"><b>https://donatonion.ir-netlify.workers.dev</b></a></p>

<p align="center">Thank you for your support in keeping this open-source project alive and actively developed! 🙏</p>

---

## Star History

<a href="https://www.star-history.com/?repos=panel-zeus%2FZ-E-U-S&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=panel-zeus/Z-E-U-S&type=date&theme=dark&legend=bottom-right&sealed_token=r3Lb_3aKfu0utexFy3xJoisRGRSGS4OCoQg3ZS5TM1QCTppem2RU8sLiVsD6UQ38Ah92MwuZU_PjyQTFM5yY3rAw14WEjtonC70muFBH4RbXxBDGIy5iIw" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=panel-zeus/Z-E-U-S&type=date&legend=bottom-right&sealed_token=r3Lb_3aKfu0utexFy3xJoisRGRSGS4OCoQg3ZS5TM1QCTppem2RU8sLiVsD6UQ38Ah92MwuZU_PjyQTFM5yY3rAw14WEjtonC70muFBH4RbXxBDGIy5iIw" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=panel-zeus/Z-E-U-S&type=date&legend=bottom-right&sealed_token=r3Lb_3aKfu0utexFy3xJoisRGRSGS4OCoQg3ZS5TM1QCTppem2RU8sLiVsD6UQ38Ah92MwuZU_PjyQTFM5yY3rAw14WEjtonC70muFBH4RbXxBDGIy5iIw" />
 </picture>
</a>

---

## <a id="license-copyright"></a>⚖️ License & Copyright

**Copyright (c) 2026 ZEUS PANEL Contributors. All Rights Reserved.**

This software is provided for **personal, non-commercial use only**. By downloading or using this software, you agree to the following strict conditions:

1. 🚫 **No Resale or Monetization:** You may not sell, rent, or lease this software, nor use it to provide commercial services (e.g., selling panel access or configurations).
2. 🚫 **No Modifications or Derivatives:** You are strictly prohibited from modifying, adapting, translating, or creating derivative works based on this source code.
3. 🚫 **No Redistribution:** You may not host, publish, or redistribute this software on any other repository, platform, or service without explicit written permission.

The source code is published solely for transparency and personal deployment. For the full legal terms, please read the [LICENSE](LICENSE) file included in this repository.

---

## <a id="credits-section"></a>Credits
This panel was originally conceptualized and authored by Arad and Morgan. The current version represents an extended, highly optimized, and heavily refactored iteration of that core logic.

* **Original Authors:** The baseline concept and initial framework belong to [AG-Morgan](https://github.com/AG-Morgan) and [aradava](https://github.com/aradava).
* **Current Maintainer:** The system upgrades, advanced network capabilities, UI redesign, and automated deployment infrastructure have been developed and maintained by [PANEL_ZEUS](https://t.me/PANEL_ZEUS).
