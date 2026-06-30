<div align="center">

<!-- هدر انیمیشنی پویا -->
<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=24&duration=3000&pause=1000&color=36BCF7&center=true&vCenter=true&width=500&lines=%E2%9A%A1+V2Ray+Configs+Collector;%F0%9F%94%84+Auto-Updated+Every+3+Hours;%F0%9F%9B%A1%EF%B8%8F+Validated+%26+Tested" alt="Typing SVG" />

<p dir="rtl">
پروژه‌ای خودکار و هوشمند جهت پایش، ارزیابی کیفیت و دسته‌بندی کانفیگ‌های فعال پروتکل‌های مختلف.
</p>

<!-- نشان‌های آماری یکپارچه -->
<p align="center">
  <img src="https://img.shields.io/github/stars/3yed-61/configs-collector?style=for-the-badge&color=FFE082&logo=github&logoColor=black" alt="Stars" />
  <img src="https://img.shields.io/github/forks/3yed-61/configs-collector?style=for-the-badge&color=81D4FA&logo=git&logoColor=black" alt="Forks" />
  <img src="https://img.shields.io/github/actions/workflow/status/3yed-61/configs-collector/main.yml?style=for-the-badge&label=Workflow&color=A5D6A7" alt="Workflow" />
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
</p>

</div>

---

<h2 dir="rtl" align="center">🏗️ ساختار پروژه</h2>

```
configs-collector/
├── .github/workflows/main.yml   ← اتوماسیون هر ۳ ساعت
├── .gitignore
├── pyproject.toml               ← پکیج‌بندی مدرن
├── requirements.txt
├── sources.txt                  ← منابع قابل‌تنظیم
├── README.md
├── src/collector/
│   ├── __init__.py              ← نسخه و اطلاعات پکیج
│   ├── __main__.py              ← نقطه ورود CLI
│   ├── config.py                ← ثابت‌ها و تنظیمات
│   ├── models.py                ← مدل داده ConfigEntry
│   ├── network.py               ← دانلود موازی + بررسی TLS
│   ├── parsers.py               ← استخراج URI/JSON و نرمال‌سازی تگ
│   ├── security.py              ← بررسی امنیتی پروتکل‌ها
│   ├── pipeline.py              ← منطق اصلی پردازش
│   └── output.py                ← نوشتن فایل‌ها و تولید آمار
├── tests/
│   ├── test_parsers.py          ← تست واحد پارسرها
│   └── test_security.py         ← تست واحد امنیت
└── classified_output/           ← خروجی (تولید خودکار)
```

---

<h2 dir="rtl" align="center">⚙️ هاب دریافت اشتراک و کدهای QR تعاملی</h2>
<p dir="rtl" align="center">
روی عنوان پروتکل مورد نظر کلیک کنید تا کارت اختصاصی، کد QR و کادر کپی لینک اشتراک نمایش داده شود.
</p>

<br>

<!-- کارت تعاملی VLESS -->
<details>
  <summary><b dir="rtl">🛡️ پروتکل VLESS (پیشنهادی)</b></summary>
  <br>
  <div align="center">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https%3A%2F%2Fraw.githubusercontent.com%2F3yed-61%2Fconfigs-collector%2Frefs%2Fheads%2Fmain%2Fclassified_output%2Fvless.txt" width="200" height="200" style="border: 2px solid #58a6ff; border-radius: 8px;" alt="VLESS QR"/>
    <br><br>
    <p dir="rtl"><b>📋 کپی آدرس اشتراک (کلیک روی دکمه‌ی کپی در گوشه کادر زیر):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/vless.txt
```

  <p dir="rtl"><b>🪶 نسخه لایت (حداکثر ۵۰ کانفیگ برتر — مناسب سیستم‌های ضعیف):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/lite/vless.txt
```

  </div>
</details>

<!-- کارت تعاملی VMESS -->
<details>
  <summary><b dir="rtl">🚀 پروتکل VMess</b></summary>
  <br>
  <div align="center">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https%3A%2F%2Fraw.githubusercontent.com%2F3yed-61%2Fconfigs-collector%2Frefs%2Fheads%2Fmain%2Fclassified_output%2Fvmess.txt" width="200" height="200" style="border: 2px solid #f0883e; border-radius: 8px;" alt="VMess QR"/>
    <br><br>
    <p dir="rtl"><b>📋 کپی آدرس اشتراک (کلیک روی دکمه‌ی کپی در گوشه کادر زیر):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/vmess.txt
```

  <p dir="rtl"><b>🪶 نسخه لایت (حداکثر ۵۰ کانفیگ برتر — مناسب سیستم‌های ضعیف):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/lite/vmess.txt
```

  </div>
</details>

<!-- کارت تعاملی TROJAN -->
<details>
  <summary><b dir="rtl">🔒 پروتکل Trojan</b></summary>
  <br>
  <div align="center">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https%3A%2F%2Fraw.githubusercontent.com%2F3yed-61%2Fconfigs-collector%2Frefs%2Fheads%2Fmain%2Fclassified_output%2Ftrojan.txt" width="200" height="200" style="border: 2px solid #bc85a3; border-radius: 8px;" alt="Trojan QR"/>
    <br><br>
    <p dir="rtl"><b>📋 کپی آدرس اشتراک (کلیک روی دکمه‌ی کپی در گوشه کادر زیر):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/trojan.txt
```

  <p dir="rtl"><b>🪶 نسخه لایت (حداکثر ۵۰ کانفیگ برتر — مناسب سیستم‌های ضعیف):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/lite/trojan.txt
```

  </div>
</details>

<!-- کارت تعاملی SHADOWSOCKS -->
<details>
  <summary><b dir="rtl">🪁 پروتکل Shadowsocks</b></summary>
  <br>
  <div align="center">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https%3A%2F%2Fraw.githubusercontent.com%2F3yed-61%2Fconfigs-collector%2Frefs%2Fheads%2Fmain%2Fclassified_output%2Fss.txt" width="200" height="200" style="border: 2px solid #a29bfe; border-radius: 8px;" alt="Shadowsocks QR"/>
    <br><br>
    <p dir="rtl"><b>📋 کپی آدرس اشتراک (کلیک روی دکمه‌ی کپی در گوشه کادر زیر):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/ss.txt
```

  </div>
</details>

<!-- کارت تعاملی HYSTERIA -->
<details>
  <summary><b dir="rtl">⚡ پروتکل Hysteria 1</b></summary>
  <br>
  <div align="center">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https%3A%2F%2Fraw.githubusercontent.com%2F3yed-61%2Fconfigs-collector%2Frefs%2Fheads%2Fmain%2Fclassified_output%2Fhysteria.txt" width="200" height="200" style="border: 2px solid #ff7675; border-radius: 8px;" alt="Hysteria QR"/>
    <br><br>
    <p dir="rtl"><b>📋 کپی آدرس اشتراک (کلیک روی دکمه‌ی کپی در گوشه کادر زیر):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/hysteria.txt
```

  </div>
</details>

<!-- کارت تعاملی HYSTERIA 2 -->
<details>
  <summary><b dir="rtl">🔥 پروتکل Hysteria 2</b></summary>
  <br>
  <div align="center">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https%3A%2F%2Fraw.githubusercontent.com%2F3yed-61%2Fconfigs-collector%2Frefs%2Fheads%2Fmain%2Fclassified_output%2Fhysteria2.txt" width="200" height="200" style="border: 2px solid #e17055; border-radius: 8px;" alt="Hysteria 2 QR"/>
    <br><br>
    <p dir="rtl"><b>📋 کپی آدرس اشتراک (کلیک روی دکمه‌ی کپی در گوشه کادر زیر):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/hysteria2.txt
```

  </div>
</details>

<!-- کارت تعاملی SOCKS -->
<details>
  <summary><b dir="rtl">🧦 پروتکل SOCKS</b></summary>
  <br>
  <div align="center">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https%3A%2F%2Fraw.githubusercontent.com%2F3yed-61%2Fconfigs-collector%2Frefs%2Fheads%2Fmain%2Fclassified_output%2Fsocks.txt" width="200" height="200" style="border: 2px solid #74b9ff; border-radius: 8px;" alt="SOCKS QR"/>
    <br><br>
    <p dir="rtl"><b>📋 کپی آدرس اشتراک (کلیک روی دکمه‌ی کپی در گوشه کادر زیر):</b></p>

```text
https://raw.githubusercontent.com/3yed-61/configs-collector/refs/heads/main/classified_output/socks.txt
```

  </div>
</details>

---

<h2 dir="rtl">🚀 نصب و اجرا</h2>

<h3 dir="rtl">اجرای سریع (بدون نصب)</h3>

```bash
# کلون مخزن
git clone https://github.com/3yed-61/configs-collector.git
cd configs-collector

# نصب وابستگی‌ها
pip install -r requirements.txt

# اجرای کلکتور
PYTHONPATH=src python -m collector
```

<h3 dir="rtl">نصب به عنوان پکیج</h3>

```bash
pip install -e .

# حالا می‌توانید از هرجایی اجرا کنید:
configs-collector
```

<h3 dir="rtl">گزینه‌های CLI</h3>

```
configs-collector [OPTIONS]

Options:
  -V, --version          نمایش نسخه
  -u, --url URL          آدرس منبع (قابل تکرار)
  -i, --infile FILE      خواندن از فایل محلی
  -o, --outdir DIR       دایرکتوری خروجی (پیش‌فرض: classified_output)
  -t, --tag TAG          تگ تزریقی در نام کانفیگ‌ها
  --only-secure          فقط کانفیگ‌های امن
  --live-check           بررسی TLS زنده سرورها
  --no-stats             بدون تولید stats.json
```

<h3 dir="rtl">اجرای تست‌ها</h3>

```bash
pip install -e ".[dev]"
pytest
```

---

<h2 dir="rtl">✨ ویژگی‌های نسخه ۲.۰</h2>

<p dir="rtl">

- 🏗️ **معماری ماژولار** — کد تمیز و قابل نگهداری با تفکیک مسئولیت‌ها
- ⚡ **دانلود موازی** — دریافت همزمان چندین منبع با `ThreadPoolExecutor`
- 📊 **تولید آمار خودکار** — فایل `stats.json` با تعداد کانفیگ هر پروتکل
- 🔧 **منابع قابل‌تنظیم** — فایل `sources.txt` به‌جای hardcode کردن URL‌ها
- 🤖 **GitHub Action** — اجرای خودکار هر ۳ ساعت و commit نتایج
- 🛡️ **بررسی امنیتی** — شناسایی cipher ضعیف، insecure flag و عدم TLS
- 🧪 **تست واحد** — پوشش تست برای پارسرها و بررسی‌های امنیتی
- 📦 **پکیج‌بندی مدرن** — قابل نصب با `pip install`

</p>

---

<h2 dir="rtl">💻 ابزارهای سازگار و راهنمای نصب</h2>

<p dir="rtl">
شما می‌توانید با کپی کردن هر یک از لینک‌های فوق و وارد کردن در بخش Subscription نرم‌افزارهای زیر، کانفیگ‌ها را دریافت نمایید:
</p>

* 🤖 **اندروید:** `v2rayNG` • `Hiddify` • `NekoBox` • `Sing-box`
* 🍏 **آی‌او‌اس (iOS):** `FoXray` • `Streisand` • `V2Box` • `Shadowrocket`
* 💻 **ویندوز:** `v2rayN` • `Nekoray` • `Hiddify`
* 🖥️ **مک (macOS):** `V2rayU` • `NekoBox` • `Hiddify` • `Sing-box`

---

<h2 dir="rtl">⚠️ سلب مسئولیت (Disclaimer)</h2>

<p dir="rtl">
هدف این پروژه افزایش حریم خصوصی و امنیت دیجیتال به‌صورت آزمایشی است. استفاده از محتوای این مخزن بر عهده خود کاربر می‌باشد و توسعه‌دهنده مسئولیتی در قبال نحوه استفاده از آن ندارد.
</p>

---

<div align="center">

<!-- نمودار تاریخچه ستاره‌های پروژه -->
[![Star History Chart](https://api.star-history.com/svg?repos=3yed-61/configs-collector&type=Date)](https://star-history.com/#3yed-61/configs-collector)

</div>
