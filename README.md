# us-proxy-harvester

پروژه خودکار گیتهاب اکشن برای جمع‌آوری، اسکن اتصال واقعی، فیلتر لوکیشن آمریکا (US)، فیلتر پینگ پایین و حداقل سرعت دانلود و انتشار خروجی **YAML (Clash/Mihomo)** و **TXT / Base64** از **100 منبع عمومی** (75 کانال تلگرام بدون نیاز به لاگین + 25 ریپازیتوری گیتهاب).

## ویژگی‌های فعال این پروژه
- **زمان‌بندی خودکار**: اجرا با Cron `0 */6 * * *` (به‌علاوه اجرای دستی از بخش Actions)
- **پروتکل‌های پشتیبانی‌شده**: VLESS, VMESS, TROJAN, SS, HYSTERIA2, TUIC
- **فیلتر لوکیشن آمریکا**: بررسی واقعی Exit-IP از طریق تانل Xray-core (سخت‌گیرانه: فقط خروجی US)
- **فیلتر پینگ پایین**: حداکثر `300 ms` (مرتب‌سازی صعودی از کمترین پینگ)
- **فیلتر حداقل سرعت دانلود**: حداقل `10 Mbps` (تست دانلود واقعی 2MB از داخل تانل)
- **بدون لاگین تلگرام**: استخراج مستقیم از پیش‌نمایش عمومی وب (`https://t.me/s/<channel>`)

## لینک‌های سابسکریپشن (پس از انتشار در ریپازیتوری عمومی)
- **Clash / Mihomo YAML**:
  `https://raw.githubusercontent.com/your-username/us-proxy-harvester/main/output/us_clash.yaml`
- **Plain TXT**:
  `https://raw.githubusercontent.com/your-username/us-proxy-harvester/main/output/us_configs.txt`
- **Base64 Subscription (v2rayNG / Hiddify / Streisand)**:
  `https://raw.githubusercontent.com/your-username/us-proxy-harvester/main/output/us_configs_base64.txt`

## راه‌اندازی سریع
1. یک ریپازیتوری **Public** در گیتهاب با نام `us-proxy-harvester` بسازید و فایل‌ها را Push کنید.
2. در تنظیمات ریپازیتوری وارد مسیر **Settings → Actions → General → Workflow permissions** شوید و گزینه **Read and write permissions** را فعال کنید.
4. از تب **Actions** ورک‌فلو `Auto-Harvest Verified US Proxy Configs` را انتخاب و روی **Run workflow** کلیک کنید.
