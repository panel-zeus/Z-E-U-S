<p align="center">
  🇬🇧 <a href="README.md">English</a> &nbsp;|&nbsp;
  🇮🇷 <a href="README.fa.md">فارسی</a>
</p>

<div align="center">
 
# ⚡ پنل زئوس (ZEUS PANEL)
[![Version](https://img.shields.io/badge/Version-v2.0.5-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/zeus-panel/ZEUS-PANEL)
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

[⚡️ ویژگی‌های کلیدی](#️-ویژگی‌ها) • [🚀 راهنمای دیپلوی سریع](#-راهنمای-دیپلوی-سریع) • [🔎 اسکنر آی‌پی تمیز](#-اسکنر-آی‌پی-تمیز) • [🛡️ پروکسی SOCKS5](#️-ساخت-پروکسی-socks5-اختصاصی-zeus-relay) • [❤️ حمایت](#-حمایت-و-دونیت) • [⚖️ لایسنس و کپی‌رایت](#لایسنس--کپی‌رایت) • [Credits](#بخش-اعتبارات)
</div>


> [!CAUTION]
> **هشدار امنیتی**
> اگر فکر می‌کنید این پروژه با دستورالعمل‌های جامعه یا سیاست‌های استفاده قابل قبول گیت‌هاب مطابقت ندارد، لطفاً به ما اطلاع دهید. ما تمام تلاش خود را می‌کنیم تا تمام پروژه‌هایمان امن و مطابق با سیاست‌های گیت‌هاب باشند.

---


## <a id="features"></a>⚡️ ویژگی‌ها و قابلیت‌ها

**🚀 پروتکل‌ها و مسیریابی اصلی**
* 📡 پشتیبانی دوگانه پروتکل: پشتیبانی بومی و بهینه‌شده از پروتکل‌های VLESS و Trojan روی WebSocket، با امکان تولید همزمان کانفیگ چندپروتکلی.
* 🌍 مسیریابی چندلوکیشنی (تا ۸ پروکسی): امکان اختصاص همزمان تا ۸ پروکسی یا موقعیت جغرافیایی مختلف به هر کاربر.
* 🔀 جایگزینی خودکار پروکسی: جایگزینی هوشمند پروکسی‌های خراب کاربر با نودهای سالم که به‌صورت پویا از مخازن پروکسی VIP دریافت می‌شوند.
* 🌐 چرخش پویای آی‌پی: چرخش خودکار آی‌پی‌های تمیز Edge کلودفلر در بازه‌های زمانی قابل تنظیم توسط کاربر (مثلاً هر ۵ دقیقه).

**🛡 ضد فیلترینگ پیشرفته و دور زدن DPI**
* 🧩 تکه‌تکه کردن پیشرفته TLS (TLS Fragmentation): پشتیبانی داخلی از Fragment با تنظیم طول و فاصله برای دور زدن بازرسی عمیق بسته‌ها (DPI).
* 🇮🇷 پریست‌های مخصوص اپراتورها: پریست‌های بهینه‌شده یک‌کلیکه برای اپراتورهای خاص (همراه‌اول، ایرانسل، رایتل، مخابرات و حالت گیمینگ).
* 🎭 یکپارچگی با Patterniha (PattN/PattNG): پشتیبانی بومی از Fragment پیشرفته JSON (fm)، Cipher Suiteهای سفارشی (cs) و Masking TLS (SNI/Host سفارشی) برای حداکثر پنهان‌کاری.
* 🕵️ شبیه‌ساز اثرانگشت ClientHello: شبیه‌سازی پویای اثرانگشت مرورگرها (کروم، سافاری، iOS، اندروید، Edge، تصادفی و Unsafe) برای دور زدن سانسور.

**👥 مدیریت پیشرفته کاربران و سیستم سهمیه**
* ⚖️ اعمال سخت‌گیرانه سهمیه: تعیین محدودیت دقیق بر اساس حجم ترافیک (گیگابایت)، انقضای زمانی (روز)، تعداد کل درخواست‌ها و تعداد دستگاه‌های همزمان (محدودیت IP).
* ⏳ شروع از اولین اتصال: امکان به تأخیر انداختن شمارش زمان اشتراک کاربر تا اولین اتصال موفق.
* ♻️ ریست خودکار سهمیه: قابلیت ریست زمان‌بندی‌شده شمارنده‌های حجم و درخواست بر اساس بازه‌های زمانی اختصاصی هر کاربر.
* 🛠 عملیات گروهی: ابزارهای جامع انتخاب چندتایی برای تغییر وضعیت، حذف و ریست سهمیه/زمان کاربران به‌صورت دسته‌ای.

**🛑 امنیت و کنترل محتوا**
* 🚫 مسدودکننده هوشمند محتوا: موتور یکپارچه DNS-over-HTTPS (DoH) برای مسدودسازی فعال محتوای NSFW (پورن) و تبلیغات به‌صورت جداگانه برای هر کاربر.
* 🔐 حفاظت احراز هویت پنل: رمز عبور پنل با هش SHA-256 و مکانیزم‌های محافظت در برابر حملات Brute-Force (مسدودسازی موقت پس از تلاش‌های ناموفق ورود).
* 🔏 ضد دستکاری و DRM: هسته ریاضی‌گونه درهم‌تنیده و بررسی‌های یکپارچگی برای جلوگیری از دستکاری کد و وایت‌لیبلینگ غیرمجاز.

**📱 رابط کاربری و اکوسیستم**
* 📲 اپلیکیشن وب پیشرو (PWA): قابلیت نصب کامل روی iOS، اندروید و دسکتاپ به‌عنوان یک برنامه مستقل با تجربه کاربری شبیه اپلیکیشن بومی.
* 🌙 رابط کاربری مدرن AMOLED: رابط واکنش‌گرا و موبایل‌فرندلی ساخته‌شده با Tailwind CSS، دارای حالت تاریک کامل AMOLED، پس‌زمینه موج‌های سه‌بعدی روان (Three.js) و عناصر تعاملی.
* 🔗 پورتال‌های سلف‌سرویس: تولید خودکار لینک‌های اشتراک قوی، کدهای QR و صفحات وضعیت لحظه‌ای اختصاصی برای هر کاربر.

**🛠 ابزارهای تشخیصی و اتوماسیون داخلی**
* 🔍 اسکنرهای داخلی: اسکنر آی‌پی تمیز یکپارچه (با اسکریپت‌های کپی-پیست برای Pydroid و CMD) و اسکنر پروکسی VIP مستقیماً داخل پنل.
* 📡 تست پینگ زنده و مستقیم: ابزار داخلی برای تست پینگ مستقیم کاربر به کلودفلر و از کلودفلر به اینترنت جهانی.
* 📊 مانیتورینگ زنده سهمیه کلودفلر: ردیابی لحظه‌ای درخواست‌های Worker کلودفلر (کل و روزانه) با نوار پیشرفت بصری برای جلوگیری پیشگیرانه از بن شدن به دلیل محدودیت ۱۰۰ هزار درخواست.
* 🔄 به‌روزرسانی هسته OTA: سیستم استقرار خودکار Edge که پنل را مستقیماً از مخزن رسمی به‌روزرسانی می‌کند بدون از دست رفتن دیتابیس یا داده‌ها.
* 🗄 سیستم پشتیبان‌گیری کامل: ابزار Export و Import کامل JSON که کل دیتابیس D1، کاربران و وضعیت پیکربندی سرور را پوشش می‌دهد.

**🤖 اتوماسیون و استقرار**
* 🚀 دیپلوی یک‌کلیکه: تأمین کامل پنل، ساب‌دامین و دیتابیس D1 مستقیماً از طریق ربات تلگرام.
* 👥 مدیریت چندحساب ربات: مدیریت همزمان چندین اکانت کلودفلر، اجرای به‌روزرسانی پنل و بازیابی امن رمز عبور.
* ☁️ بهینه‌شده برای اکوسیستم کلودفلر: طراحی‌شده کاملاً در محدوده محدودیت‌های کلودفلر، با استفاده از Connection Pooling هوشمند D1 و مکانیزم‌های Queue Batching برای حداکثر کارایی عملیاتی.


---

# 🚀 راهنمای دیپلوی سریع

<div align="center">

<a href="https://dash.cloudflare.com/" target="_blank">
<img src="https://img.shields.io/badge/Cloudflare_Dashboard-Login-f38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Cloudflare Dashboard" height="40">
</a>

<div align="center">
ابتدا وارد داشبورد کلودفلر خود شوید. مطمئن شوید از ایمیل تأییدشده استفاده می‌کنید، سپس روش دیپلوی زیر را دنبال کنید.
</div>

<br>

<a href="https://t.me/ZEUS_PANEL_BOT" target="_blank">
<img src="https://img.shields.io/badge/Zeus_Telegram_Bot-Start_Bot-0088cc?style=for-the-badge&logo=telegram&logoColor=white" alt="Zeus Telegram Bot" height="40">
</a>

</div>

<br>

## 🤖 دیپلوی از طریق ربات تلگرام

1. 🌐 وارد **[ربات تلگرام زئوس](https://t.me/ZEUS_PANEL_BOT)** شوید و روی `Start` کلیک کنید.
2. 👤 از منوی اصلی روی **"➕ Register Cloudflare Account"** کلیک کنید.
3. 🔗 روی دکمه اینلاین **"🔑 Get Cloudflare Token"** کلیک کنید تا به اکانت کلودفلر خود هدایت شوید.
4. 🟦 به پایین صفحه کلودفلر اسکرول کنید، روی دکمه آبی `Continue to summary` کلیک کنید و سپس `Create Token` را بزنید.
5. 🔑 توکن تولیدشده را کپی کرده و **مستقیماً در چت ربات ارسال کنید**.
6. ⚡️ پس از تأیید توکن، به منوی اصلی برگردید، روی **"🚀 Build New Panel"** کلیک کنید و اکانت خود را انتخاب کنید. دیتابیس D1 و پنل شما به‌طور خودکار مستقر خواهد شد.

---

> [!CAUTION]
> **هشدار امنیتی حیاتی:** حتماً رمز عبور مدیریتی اولیه‌ای که در اولین ورود به پنل تنظیم می‌کنید را به‌صورت امن ذخیره کنید. آن را گم نکنید!

---


# 🛡️ ساخت پروکسی SOCKS5 اختصاصی (Zeus Relay)

یک اسکریپت bash اختصاصی برای استقرار فوری یک پروکسی SOCKS5 خصوصی و امن روی هر VPS لینوکسی (اوبونتو، دبیان، سنت‌او‌اس، راکی لینوکس) ارائه شده است. این کار به‌شدت برای کاربرانی که می‌خواهند پروکسی‌های مسکونی VIP برای مسیریابی ترافیک از طریق آی‌پی‌های تمیز و اختصاصی بسازند، توصیه می‌شود.

برای نصب، به‌روزرسانی یا حذف پروکسی Dante SOCKS5، دستور زیر را با دسترسی root روی سرور لینوکس خود اجرا کنید:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/main/zeus-relay.sh | sed 's/\r$//')
```

این اسکریپت دارای منوی تعاملی، پیکربندی خودکار پورت، تولید تصادفی و امن نام کاربری/رمز عبور و پشتیبانی بومی از IPv4/IPv6 است.

---

# 🔎 اسکنر آی‌پی تمیز

پنل زئوس دارای یک اسکنر آی‌پی محلی بسیار بهینه‌شده و چندنخی است. می‌توانید سریع‌ترین و پایدارترین آی‌پی‌های تمیز کلودفلر را مستقیماً از دستگاه خود با روش‌های زیر پیدا کنید:

### 📱 کاربران موبایل (Pydroid 3 - اندروید)
1. اپلیکیشن **[Pydroid 3](https://play.google.com/store/apps/details?id=ru.iiec.pydroid3)** را از فروشگاه گوگل‌پلی نصب کنید.
2. اپ را باز کنید، از منوی کناری به **Terminal** بروید و دستور زیر را اجرا کنید:

```bash
python -c "import urllib.request; req = urllib.request.Request('https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/zeus-scanner.txt', headers={'User-Agent': 'Mozilla/5.0'}); exec(urllib.request.urlopen(req).read().decode('utf-8').split('---PYTH' + 'ON---')[1].split('---POWERSHELL---')[0].strip())"

```

3. پس از راه‌اندازی سرور، آدرس `http://127.0.0.1:8000` را در مرورگر خود باز کنید.

### 💻 کاربران ویندوز (CMD / PowerShell)

**Command Prompt (CMD)** را در ویندوز باز کنید، دستور زیر را پیست کنید و Enter بزنید. رابط اسکنر پرسرعت به‌طور خودکار کامپایل و راه‌اندازی می‌شود:

```cmd
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13; $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $text = ($wc.DownloadString('https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/zeus-scanner.txt') -split '---POWERSHELL---')[1].Trim(); [IO.File]::WriteAllText('zeus-scanner.ps1', $text, [System.Text.Encoding]::UTF8); .\zeus-scanner.ps1"

```

---


# 💰 حمایت و دونیت

<p align="center">ساخته‌شده با ❤️</p>

<p align="center"><a href="https://donatonion.ir-netlify.workers.dev"><b>https://donatonion.ir-netlify.workers.dev</b></a></p>

<p align="center">از حمایت شما برای زنده نگه‌داشتن و توسعه فعال این پروژه اوپن‌سورس سپاسگزاریم! 🙏</p>

---

## تاریخچه ستاره‌ها

<a href="https://www.star-history.com/?repos=panel-zeus%2FZ-E-U-S&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=panel-zeus/Z-E-U-S&type=date&theme=dark&legend=bottom-right&sealed_token=r3Lb_3aKfu0utexFy3xJoisRGRSGS4OCoQg3ZS5TM1QCTppem2RU8sLiVsD6UQ38Ah92MwuZU_PjyQTFM5yY3rAw14WEjtonC70muFBH4RbXxBDGIy5iIw" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=panel-zeus/Z-E-U-S&type=date&legend=bottom-right&sealed_token=r3Lb_3aKfu0utexFy3xJoisRGRSGS4OCoQg3ZS5TM1QCTppem2RU8sLiVsD6UQ38Ah92MwuZU_PjyQTFM5yY3rAw14WEjtonC70muFBH4RbXxBDGIy5iIw" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=panel-zeus/Z-E-U-S&type=date&legend=bottom-right&sealed_token=r3Lb_3aKfu0utexFy3xJoisRGRSGS4OCoQg3ZS5TM1QCTppem2RU8sLiVsD6UQ38Ah92MwuZU_PjyQTFM5yY3rAw14WEjtonC70muFBH4RbXxBDGIy5iIw" />
 </picture>
</a>

---

## <a id="license-copyright"></a>⚖️ لایسنس و کپی‌رایت

**حق چاپ (c) ۲۰۲۶ مشارکت‌کنندگان پنل زئوس. تمامی حقوق محفوظ است.**

این نرم‌افزار فقط برای **استفاده شخصی و غیرتجاری** ارائه شده است. با دانلود یا استفاده از این نرم‌افزار، با شرایط سخت‌گیرانه زیر موافقت می‌کنید:

1. 🚫 **ممنوعیت فروش یا کسب درآمد:** حق فروش، اجاره یا اجاره دادن این نرم‌افزار و همچنین استفاده از آن برای ارائه خدمات تجاری (مثل فروش دسترسی به پنل یا کانفیگ) را ندارید.
2. 🚫 **ممنوعیت تغییر یا مشتق‌سازی:** تغییر، تطبیق، ترجمه یا ایجاد آثار مشتق بر اساس این سورس‌کد به‌شدت ممنوع است.
3. 🚫 **ممنوعیت توزیع مجدد:** حق میزبانی، انتشار یا توزیع مجدد این نرم‌افزار در هر مخزن، پلتفرم یا سرویس دیگری بدون اجازه کتبی صریح را ندارید.

سورس‌کد صرفاً برای شفافیت و دیپلوی شخصی منتشر شده است. برای شرایط کامل قانونی، لطفاً فایل [LICENSE](LICENSE) موجود در این مخزن را مطالعه کنید.

---

## <a id="credits-section"></a>بخش اعتبارات
این پنل در ابتدا توسط آراد و مورگان مفهوم‌سازی و نوشته شده است. نسخه فعلی نمایانگر یک تکرار گسترش‌یافته، بسیار بهینه‌شده و به‌شدت بازسازی‌شده از آن منطق اصلی است.

* **نویسندگان اصلی:** مفهوم پایه و چارچوب اولیه متعلق به [AG-Morgan](https://github.com/AG-Morgan) و [aradava](https://github.com/aradava) است.
* **نگهدارنده فعلی:** ارتقاهای سیستم، قابلیت‌های پیشرفته شبکه، بازطراحی رابط کاربری و زیرساخت دیپلوی خودکار توسط [PANEL_ZEUS](https://t.me/PANEL_ZEUS) توسعه و نگهداری شده است.
