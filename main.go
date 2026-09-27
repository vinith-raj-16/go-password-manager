package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"unicode"
)

const (
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	numberChars  = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Expected 'check' or 'generate' subcommands")
		os.Exit(1)
	}

	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)

	generateCmd := flag.NewFlagSet("generate", flag.ExitOnError)
	genLength := generateCmd.Int("length", 16, "Length of the password (16-24)")
	genNoSymbols := generateCmd.Bool("no-symbols", false, "Exclude special characters")
	genSlack := generateCmd.Bool("slack", false, "Send generated password to Slack")

	switch os.Args[1] {
	case "check":
		checkCmd.Parse(os.Args[2:])
		if checkCmd.NArg() < 1 {
			fmt.Println("Please provide a password to check")
			os.Exit(1)
		}
		password := checkCmd.Arg(0)
		feedback := checkPasswordStrength(password)
		if len(feedback) > 0 {
			fmt.Println("Password failed checks:")
			for _, f := range feedback {
				fmt.Printf("- %s\n", f)
			}
			os.Exit(1)
		}
		fmt.Println("Password is strong and secure!")

	case "generate":
		generateCmd.Parse(os.Args[2:])
		pwd := generatePassword(*genLength, *genNoSymbols)
		fmt.Printf("Generated Password: %s\n", pwd)

		if *genSlack {
			webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
			if webhookURL == "" {
				webhookURL = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK_URL" // Do NOT commit real tokens!
			}
			sendToSlack(pwd, webhookURL)
		}
	default:
		fmt.Println("Expected 'check' or 'generate' subcommands")
		os.Exit(1)
	}
}

func checkPasswordStrength(password string) []string {
	var feedback []string

	if len(password) < 12 {
		feedback = append(feedback, "Too short (minimum 12 characters required).")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		if unicode.IsUpper(c) {
			hasUpper = true
		} else if unicode.IsLower(c) {
			hasLower = true
		} else if unicode.IsDigit(c) {
			hasDigit = true
		} else if unicode.IsPunct(c) || unicode.IsSymbol(c) {
			hasSpecial = true
		}
	}

	if !hasUpper {
		feedback = append(feedback, "Missing uppercase letter.")
	}
	if !hasLower {
		feedback = append(feedback, "Missing lowercase letter.")
	}
	if !hasDigit {
		feedback = append(feedback, "Missing number.")
	}
	if !hasSpecial {
		feedback = append(feedback, "Missing special character.")
	}

	if len(feedback) == 0 {
		if checkHIBP(password) {
			feedback = append(feedback, "Found in breach database (HIBP).")
		}
	}

	return feedback
}

func checkHIBP(password string) bool {
	hasher := sha1.New()
	hasher.Write([]byte(password))
	hash := fmt.Sprintf("%X", hasher.Sum(nil))

	prefix := hash[:5]
	suffix := hash[5:]

	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking HIBP API: %v\n", err)
		return false // Fail open if API fails
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "HIBP API returned status: %d\n", resp.StatusCode)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading HIBP API response: %v\n", err)
		return false
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) >= 1 && parts[0] == suffix {
			return true
		}
	}

	return false
}

func generatePassword(length int, noSymbols bool) string {
	if length < 16 {
		length = 16
	} else if length > 24 {
		length = 24
	}

	allChars := upperChars + lowerChars + numberChars
	if !noSymbols {
		allChars += specialChars
	}

	for {
		pwd := make([]byte, length)
		for i := 0; i < length; i++ {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
			if err != nil {
				panic(err)
			}
			pwd[i] = allChars[n.Int64()]
		}

		pwdStr := string(pwd)

		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, c := range pwdStr {
			if unicode.IsUpper(c) {
				hasUpper = true
			} else if unicode.IsLower(c) {
				hasLower = true
			} else if unicode.IsDigit(c) {
				hasDigit = true
			} else if strings.ContainsRune(specialChars, c) {
				hasSpecial = true
			}
		}

		if hasUpper && hasLower && hasDigit && (hasSpecial || noSymbols) {
			return pwdStr
		}
	}
}

func sendToSlack(password string, webhookURL string) {
	payload := map[string]string{
		"text": fmt.Sprintf("New generated password: `%s`", password),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal Slack payload: %v\n", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send to Slack: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println("Password successfully sent to Slack.")
	} else {
		fmt.Fprintf(os.Stderr, "Failed to send to Slack, status code: %d\n", resp.StatusCode)
	}
}
