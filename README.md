# Swiss Security Knife
Collection of common security tools

## Password Security Checker
Go-based web application for checking password strength against security best practices.

### Quick Start
```bash
go run main.go
```

### Security Requirements
- ✓ Minimum 12 characters
- ✓ Uppercase letter (A-Z)
- ✓ Lowercase letter (a-z)
- ✓ Number (0-9)
- ✓ Special character (!@#$%^&*)
- ✓ Not a common password
- ✓ No repeated characters (3+ consecutive)
- ✓ No sequential patterns (abc, 123, qwerty)

### Results
The checker displays:
- **Strength badge**: Weak, Fair, Good, or Strong
- **Score**: X/8 requirements met
- **Detailed checklist**: ✓ or ❌ for each requirement

### Requirements
- Go 1.21 or higher
