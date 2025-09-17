# 📧 EmailValidationApi

A lightweight **Email Validation API** built with **C# Minimal API**.  
This service allows you to validate email addresses through a REST endpoint — checking whether an email has a valid format.

---

## 🚀 Features
- ✅ Validate email format using **Regex**
- ⚡ Fast & lightweight — powered by **.NET Minimal API**
- 📖 Built-in **Swagger / OpenAPI** documentation
- 🐳 Ready to run in **Docker**

---

## 🛠️ Tech Stack
- **.NET 8 / C# Minimal API**
- **Regex** for validation
- **Swagger** for API docs
- **Docker** for containerization

## 🔌 ZeroBounce Integration

This project integrates with the [ZeroBounce.SDK](https://www.nuget.org/packages/ZeroBounce.SDK),  
a powerful email validation service that provides more than simple regex checks.

With **ZeroBounce**, the API can:
- 🔍 Detect if an email address is **valid or invalid**
- 🚫 Identify **abuse, spam traps, and disposable emails**
- 🏢 Validate **MX records** and domain configuration
- 🌍 Detect **role-based accounts** (like support@, info@, etc.)
- 📊 Provide additional metadata (e.g., domain information)

This makes the validation much more **reliable and production-ready** compared to basic regex-only solutions.
