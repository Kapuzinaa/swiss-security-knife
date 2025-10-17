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

// PageData represents data passed to the template
type PageData struct {
	Password string
	Result   *PasswordResponse
}

// Common passwords list
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

// Sequential patterns
var sequentialPatterns = []string{
	"abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk",
	"jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst",
	"stu", "tuv", "uvw", "vwx", "wxy", "xyz",
	"012", "123", "234", "345", "456", "567", "678", "789",
	"qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop",
	"asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl",
	"zxc", "xcv", "cvb", "vbn", "bnm",
}

// PasswordValidator handles all password validation logic
type PasswordValidator struct{}

// CheckLength validates minimum password length (12 characters)
func (pv *PasswordValidator) CheckLength(password string) bool {
	return len(password) >= 12
}

// CheckUppercase validates presence of uppercase letters
func (pv *PasswordValidator) CheckUppercase(password string) bool {
	for _, char := range password {
		if unicode.IsUpper(char) {
			return true
		}
	}
	return false
}

// CheckLowercase validates presence of lowercase letters
func (pv *PasswordValidator) CheckLowercase(password string) bool {
	for _, char := range password {
		if unicode.IsLower(char) {
			return true
		}
	}
	return false
}

// CheckNumber validates presence of numbers
func (pv *PasswordValidator) CheckNumber(password string) bool {
	for _, char := range password {
		if unicode.IsDigit(char) {
			return true
		}
	}
	return false
}

// CheckSpecial validates presence of special characters
func (pv *PasswordValidator) CheckSpecial(password string) bool {
	specialChars := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
	return specialChars.MatchString(password)
}

// CheckCommon validates password is not a common password
func (pv *PasswordValidator) CheckCommon(password string) bool {
	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if strings.Contains(lowerPassword, common) || strings.Contains(common, lowerPassword) {
			return false
		}
	}
	return true
}

// CheckRepeated validates no repeated characters (3 or more consecutive)
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

// CheckSequential validates no sequential character patterns
func (pv *PasswordValidator) CheckSequential(password string) bool {
	lowerPassword := strings.ToLower(password)

	for _, pattern := range sequentialPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return false
		}
		// Check reverse pattern
		reversed := reverseString(pattern)
		if strings.Contains(lowerPassword, reversed) {
			return false
		}
	}
	return true
}

// Validate performs all validation checks
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

	// Calculate score
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

	// Determine strength
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

	valid := score == 8

	return PasswordResponse{
		Valid:    valid,
		Strength: strength,
		Score:    score,
		Results:  results,
		Message:  message,
	}
}

// reverseString reverses a string
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Handler for the main page
func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the template
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Initialize page data
	data := PageData{}

	// Handle form submission
	if r.Method == http.MethodPost {
		password := r.FormValue("password")
		data.Password = password

		if password != "" {
			validator := &PasswordValidator{}
			result := validator.Validate(password)
			data.Result = &result
		}
	}

	// Render the template
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func main() {
	// Route handlers
	http.HandleFunc("/", indexHandler)

	port := ":8080"
	log.Printf("Server starting on port %s", port)
	log.Printf("Access the password checker at http://localhost%s", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
