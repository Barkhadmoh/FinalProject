# FinalProject 🔐
Web App Penetration and Hardening - Final Project SENG 473

## Team Members
| Name | Student ID |
|------|------------|
| Barkhad Mohamed | 210208908 |
| Sabrin Ali Isack | 210208994 |
| Sadik Hassan Ismail | 220208742 |

## Topic
Web App Penetration & Hardening

## What This Project Does
### Attacks Demonstrated:
- Attack 1: No Token Attack — accessing protected routes without token
- Attack 2: Brute Force Attack — wrong password 5 times locks account
- Attack 3: JWT Tamper Attack — modified token gets rejected

### Security Hardening Applied:
- Token validation on all protected routes
- Brute force protection — account locks after 5 failed attempts
- JWT signature verification — tampered tokens rejected
- Input validation — empty fields rejected
- Security logging — all attacks logged to security.log

## How to Run
1. Install requirements:
pip install flask pyjwt flask-bcrypt

2. Run the app:
python app.py

3. Server runs at: http://localhost:5000

## API Endpoints
| Method | Endpoint | Access |
|--------|----------|--------|
| POST | /register | Public |
| POST | /login | Public |
| GET | /profile | User + Admin |
| DELETE | /user/<id> | Admin only |
| POST | /logout | User + Admin |
