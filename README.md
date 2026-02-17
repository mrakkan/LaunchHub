# LaunchHub

แพลตฟอร์มช่วย Deploy แอป/เว็บ/ API แบบง่ายบนเครื่องของคุณ โดยใช้ Django เป็นแผงควบคุมและ Docker สำหรับการรันจริง รองรับการเชื่อมต่อ GitHub, ตั้งค่า Webhook เพื่อทำ Deploy อัตโนมัติเมื่อมีการ Push โค้ด, แสดงสถานะและ Log ของการ Deploy พร้อมปุ่ม Preview เพื่อเปิดดูผลลัพธ์ได้ทันที

## คุณสมบัติเด่น
- สร้างโปรเจกต์จาก GitHub Repository ได้ทันที (กรอก URL ของ repo)
- เชื่อมต่อบัญชี GitHub ด้วย OAuth และขอสิทธิ์ `repo` + `admin:repo_hook` สำหรับอ่าน repo และสร้าง/จัดการ webhook อัตโนมัติในอนาคต
- รองรับ GitHub Webhook (เหตุการณ์ `push`) เพื่อ Trigger Deploy อัตโนมัติ พร้อมตรวจสอบลายเซ็น HMAC ตาม `project.webhook_token`
- ขั้นตอน Deploy แบบมีสเตจจิ้ง (staging) ตรวจสุขภาพก่อนสลับทราฟฟิก ลด Downtime
- แสดง Preview URL และสถานะคอนเทนเนอร์ พร้อมแดชบอร์ดสำหรับดูโปรเจกต์และประวัติการ Deploy
- แชร์การเข้าถึงจากเครื่องอื่นใน LAN ได้ และสามารถเปิดสาธารณะผ่าน Tunnel เช่น Cloudflare/Ngrok โดยไม่ต้องทำ Port Forwarding

## เริ่มต้นใช้งาน
### ข้อกำหนดระบบ
- Python 3.11 ขึ้นไป
- Docker (สำหรับการ Deploy และรันคอนเทนเนอร์)
- Git

### ติดตั้งและรัน
1) สร้างและเปิดใช้งาน virtual environment และติดตั้ง dependency
```
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

2) ตั้งค่า GitHub OAuth ในไฟล์ `deploy_platform/settings.py` หรือผ่าน Environment variables (แนะนำ)
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_REDIRECT_URI` ค่าเริ่มต้นคือ `/github/callback/`

3) เตรียมฐานข้อมูลและรันเซิร์ฟเวอร์
```
python manage.py migrate
python manage.py runserver
```
เปิดใช้งานที่ `http://127.0.0.1:8000/` หรือจากเครื่องอื่นใน LAN ใช้ `http://<IP เครื่องคุณ>:8000/` (โปรดอนุญาต Windows Firewall ตามพอร์ตที่ใช้งาน)

## เชื่อมต่อ GitHub (OAuth)
- ไปที่หน้า Login แล้วกด “Login with GitHub” หรือเชื่อม GitHub ในหน้าโปรไฟล์
- ระบบจะขอสิทธิ์ `user:email repo admin:repo_hook` เพื่อใช้งาน repo และสร้าง/จัดการ webhook
- หลังเชื่อมต่อสำเร็จ ระบบจะเก็บ `access_token` และ scopes ที่ได้รับไว้ใน `SocialAccount.extra_data`

## ตั้งค่า GitHub Webhook (ปัจจุบัน: ตั้งเอง)
ระบบมี endpoint รับ Webhook ที่ `POST /webhook/github/<project_id>/` รองรับเหตุการณ์ `push` และตรวจ HMAC ตาม secret (`project.webhook_token`).

ขั้นตอนตั้งค่าใน GitHub Repo:
- เปิด `Settings` → `Webhooks` → “Add webhook”
- Payload URL: `https://<โดเมนหรือ tunnel>/webhook/github/<project_id>/`
- Content type: `application/json`
- Secret: ใช้ค่าที่กำหนดใน `project.webhook_token`
- Events: เลือก “Just the push event”
- (ทางเลือก) กำหนด Branch ที่จะทริกเกอร์ใน `project.webhook_branch` (เช่น `main`)

หมายเหตุ: เรามีแผนเพิ่มปุ่ม “Enable Webhook” เพื่อสร้าง webhook อัตโนมัติด้วยสิทธิ์ `admin:repo_hook` ในอนาคต

## การ Deploy ด้วย Docker (ภาพรวม)
- ระบบจะ Build image จากโค้ดใน repo และรันคอนเทนเนอร์แบบ staging เพื่อตรวจสุขภาพ
- เมื่อสุขภาพผ่าน จะสลับทราฟฟิกไปยังคอนเทนเนอร์ใหม่ด้วย Downtime ต่ำ
- ภายในคอนเทนเนอร์ แอปควรรันบน `0.0.0.0` และอ่านพอร์ตจากตัวแปรแวดล้อม `PORT` (แนวทางเหมือน PaaS)
- ตัวอย่าง `fastapi-app/Dockerfile` ใช้ `uvicorn` รันบน `0.0.0.0:80` ตามแนวปฏิบัติ


## โครงสร้างโปรเจกต์
- `deploy_platform/` การตั้งค่า Django ทั้งหมด (settings/urls/wsgi/asgi)
- `core/` โมดูลหลัก: models, views, forms, urls, migrations
- `templates/core/` เทมเพลต UI (dashboard, login, profile, project pages ฯลฯ)
- `static/` ไฟล์ CSS/JS/รูป
- `manage.py` สคริปต์จัดการ Django


