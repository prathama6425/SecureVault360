---
description: Repository Information Overview
alwaysApply: true
---

# Securevault Information

## Summary
A comprehensive Django-based secure file vault application that implements multi-layer security for file uploads including type validation, malware scanning with ClamAV, sensitive data detection, and complete audit logging.
It is a web-based secure data management system designed to protect user files and sensitive information.
It uses Multi-Factor Authentication (MFA) and AES-based encryption, and file scanning to ensure safe authentication and protected file storage.

## Structure
The project is organized into several Django apps and supporting directories:

- **accounts/**: User authentication and account management
- **files/**: File upload, security checking, and audit functionality
- **vault/**: Core vault operations and data management
- **securevault360/**: Django project configuration and settings
- **static/**: Static assets (CSS, JS, images)
- **templates/**: HTML templates for the web interface
- **media/**: User-uploaded files storage

## Language & Runtime
**Language**: Python  
**Version**: 3.12.4  
**Framework**: Django 5.0.7  
**Build System**: Django management commands  
**Package Manager**: pip  

## Dependencies
**Main Dependencies**:  
- Django>=5.0,<6.0  
- python-decouple>=3.8  
- cryptography>=42.0  
- pyotp>=2.9.0  
- pyclamd>=0.4.0  

## Build & Installation
```bash
pip install -r requirements.txt
python manage.py migrate
```

## Main Entry Points
- **Web Application**: `python manage.py runserver`  
- **Management Script**: `manage.py`  

## Testing
**Framework**: Django Test Framework  
**Test Location**: `accounts/tests.py`, `files/tests.py`, `vault/tests.py`  
**Run Command**:  
```bash
python manage.py test
```