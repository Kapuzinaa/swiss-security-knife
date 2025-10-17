package main

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// ValidationResult represents individual check results
type ValidationResult struct {
	Length     bool
	Uppercase  bool
	Lowercase  bool
	Number     bool
	Special    bool
	Common     bool
	Repeated   bool
	Sequential bool
}

// PasswordResponse represents the validation response
type PasswordResponse struct {
	Valid    bool
	Strength string
	Score    int
	Results  ValidationResult
	Message  string
}

// HashMatch represents a possible hash type match
type HashMatch struct {
	Name     string
	Length   int
	Security string
}

// HashResult represents the hash identification result
type HashResult struct {
	Length  int
	CharSet string
	Matches []HashMatch
}

// PasswordPageData for password checker page
type PasswordPageData struct {
	Password string
	Result   *PasswordResponse
}

// HashPageData for hash identifier page
type HashPageData struct {
	Hash   string
	Result *HashResult
}

var commonPasswords = []string{
	"password", "123456", "123456789", "12345678", "12345", "1234567",
	"password1", "123123", "1234567890", "000000", "qwerty", "abc123",
	"million2", "password123", "1234", "iloveyou", "aaron431", "qwertyuiop",
	"123321", "monkey", "dragon", "654321", "666666", "123", "121212",
	"master", "sunshine", "princess", "welcome", "login", "admin",
	"qwerty123", "solo", "passw0rd", "starwars", "letmein", "123456a",
	"monkey1", "shadow", "sunshine1", "password1234", "123123123",
	"password12", "1q2w3e4r", "batman", "trustno1", "ranger", "thomas",
}

var sequentialPatterns = []string{
	"abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk",
	"jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst",
	"stu", "tuv", "uvw", "vwx", "wxy", "xyz",
	"012", "123", "234", "345", "456", "567", "678", "789",
	"qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop",
	"asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl",
	"zxc", "xcv", "cvb", "vbn", "bnm",
}

type PasswordValidator struct{}

func (pv *PasswordValidator) CheckLength(password string) bool {
	return len(password) >= 12
}

func (pv *PasswordValidator) CheckUppercase(password string) bool {
	for _, char := range password {
		if unicode.IsUpper(char) {
			return true
		}
	}
	return false
}

func (pv *PasswordValidator) CheckLowercase(password string) bool {
	for _, char := range password {
		if unicode.IsLower(char) {
			return true
		}
	}
	return false
}

func (pv *PasswordValidator) CheckNumber(password string) bool {
	for _, char := range password {
		if unicode.IsDigit(char) {
			return true
		}
	}
	return false
}

func (pv *PasswordValidator) CheckSpecial(password string) bool {
	specialChars := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
	return specialChars.MatchString(password)
}

func (pv *PasswordValidator) CheckCommon(password string) bool {
	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if strings.Contains(lowerPassword, common) || strings.Contains(common, lowerPassword) {
			return false
		}
	}
	return true
}

func (pv *PasswordValidator) CheckRepeated(password string) bool {
	runes := []rune(password)
	if len(runes) < 3 {
		return true
	}
	for i := 0; i < len(runes)-2; i++ {
		if runes[i] == runes[i+1] && runes[i] == runes[i+2] {
			return false
		}
	}
	return true
}

func (pv *PasswordValidator) CheckSequential(password string) bool {
	lowerPassword := strings.ToLower(password)
	for _, pattern := range sequentialPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return false
		}
		reversed := reverseString(pattern)
		if strings.Contains(lowerPassword, reversed) {
			return false
		}
	}
	return true
}

func (pv *PasswordValidator) Validate(password string) PasswordResponse {
	results := ValidationResult{
		Length:     pv.CheckLength(password),
		Uppercase:  pv.CheckUppercase(password),
		Lowercase:  pv.CheckLowercase(password),
		Number:     pv.CheckNumber(password),
		Special:    pv.CheckSpecial(password),
		Common:     pv.CheckCommon(password),
		Repeated:   pv.CheckRepeated(password),
		Sequential: pv.CheckSequential(password),
	}

	score := 0
	if results.Length {
		score++
	}
	if results.Uppercase {
		score++
	}
	if results.Lowercase {
		score++
	}
	if results.Number {
		score++
	}
	if results.Special {
		score++
	}
	if results.Common {
		score++
	}
	if results.Repeated {
		score++
	}
	if results.Sequential {
		score++
	}

	strength := "weak"
	message := "Password does not meet security requirements"
	percentage := (score * 100) / 8

	if percentage >= 90 {
		strength = "strong"
		message = "Password meets all security requirements"
	} else if percentage >= 60 {
		strength = "good"
		message = "Password is acceptable but could be stronger"
	} else if percentage >= 40 {
		strength = "fair"
		message = "Password needs improvement"
	}

	return PasswordResponse{
		Valid:    score == 8,
		Strength: strength,
		Score:    score,
		Results:  results,
		Message:  message,
	}
}

type HashIdentifier struct{}

func (hi *HashIdentifier) Identify(hash string) HashResult {
	hash = strings.TrimSpace(hash)
	length := len(hash)

	var charSet string
	if regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(hash) {
		charSet = "Hexadecimal"
	} else if regexp.MustCompile(`^[A-Za-z0-9+/=]+$`).MatchString(hash) {
		charSet = "Base64"
	} else if strings.HasPrefix(hash, "$") {
		charSet = "Modular Crypt Format"
	} else {
		charSet = "Mixed/Unknown"
	}

	matches := []HashMatch{}

	if charSet == "Hexadecimal" {
		switch length {
		case 32:
			matches = append(matches, HashMatch{"MD5", 32, "Weak - Not recommended"})
			matches = append(matches, HashMatch{"NTLM", 32, "Weak - Not recommended"})
		case 40:
			matches = append(matches, HashMatch{"SHA-1", 40, "Weak - Deprecated"})
			matches = append(matches, HashMatch{"RIPEMD-160", 40, "Moderate"})
		case 56:
			matches = append(matches, HashMatch{"SHA-224", 56, "Moderate"})
		case 64:
			matches = append(matches, HashMatch{"SHA-256", 64, "Strong"})
			matches = append(matches, HashMatch{"BLAKE2s-256", 64, "Strong"})
		case 96:
			matches = append(matches, HashMatch{"SHA-384", 96, "Strong"})
		case 128:
			matches = append(matches, HashMatch{"SHA-512", 128, "Strong"})
			matches = append(matches, HashMatch{"BLAKE2b-512", 128, "Strong"})
		}
	}

	if strings.HasPrefix(hash, "$") {
		if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
			matches = append(matches, HashMatch{"bcrypt", length, "Strong - Recommended"})
		} else if strings.HasPrefix(hash, "$6$") {
			matches = append(matches, HashMatch{"SHA-512 Crypt", length, "Strong"})
		} else if strings.HasPrefix(hash, "$5$") {
			matches = append(matches, HashMatch{"SHA-256 Crypt", length, "Strong"})
		} else if strings.HasPrefix(hash, "$1$") {
			matches = append(matches, HashMatch{"MD5 Crypt", length, "Weak"})
		} else if strings.HasPrefix(hash, "$argon2") {
			matches = append(matches, HashMatch{"Argon2", length, "Very Strong - Recommended"})
		} else if strings.HasPrefix(hash, "$scrypt$") {
			matches = append(matches, HashMatch{"scrypt", length, "Strong"})
		}
	}

	if charSet == "Base64" {
		switch length {
		case 24:
			matches = append(matches, HashMatch{"MD5 (Base64)", 24, "Weak"})
		case 28:
			matches = append(matches, HashMatch{"SHA-1 (Base64)", 28, "Weak"})
		case 44:
			matches = append(matches, HashMatch{"SHA-256 (Base64)", 44, "Strong"})
		case 88:
			matches = append(matches, HashMatch{"SHA-512 (Base64)", 88, "Strong"})
		}
	}

	return HashResult{
		Length:  length,
		CharSet: charSet,
		Matches: matches,
	}
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func passwordHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/password.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := PasswordPageData{}

	if r.Method == http.MethodPost {
		password := r.FormValue("password")
		data.Password = password

		if password != "" {
			validator := &PasswordValidator{}
			result := validator.Validate(password)
			data.Result = &result
		}
	}

	tmpl.Execute(w, data)
}

func hashHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/hash.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := HashPageData{}

	if r.Method == http.MethodPost {
		hash := r.FormValue("hash")
		data.Hash = hash

		if hash != "" {
			identifier := &HashIdentifier{}
			result := identifier.Identify(hash)
			data.Result = &result
		}
	}

	tmpl.Execute(w, data)
}

func main() {
	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Page handlers
	http.HandleFunc("/", passwordHandler)
	http.HandleFunc("/hash-identifier", hashHandler)

	port := ":8080"
	log.Printf("Server starting on port %s", port)
	log.Printf("Password Checker: http://localhost%s", port)
	log.Printf("Hash Identifier:  http://localhost%s/hash-identifier", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
