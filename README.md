# Swiss Security Knife
Collection of common security tools

## Tools

### 🔒 Password Security Checker
Check password strength against security best practices with real-time validation.

### 🔍 Hash Identifier
Identify hash algorithms by analyzing hash length and character patterns.

## Quick Start
```bash
go run main.go
```

Open `http://localhost:8080` in your browser.

## Features

**Password Checker:**
- Minimum 12 characters
- Uppercase, lowercase, numbers, special chars
- Common password detection
- No repeated/sequential patterns

**Hash Identifier:**
- Identifies MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, and more
- Detects hash format (Hex, Base64, Modular Crypt)
- Security recommendations for each hash type
- Examples of common hash formats

## Requirements
- Go 1.21 or higher
