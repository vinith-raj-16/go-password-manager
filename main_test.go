package main

import (
	"strings"
	"testing"
)

func TestCheckPasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected []string
	}{
		{
			name:     "Too short",
			password: "Short1!",
			expected: []string{"Too short (minimum 12 characters required)."},
		},
		{
			name:     "Missing uppercase",
			password: "nouppercase1!",
			expected: []string{"Missing uppercase letter."},
		},
		{
			name:     "Missing lowercase",
			password: "NOLOWERCASE1!",
			expected: []string{"Missing lowercase letter."},
		},
		{
			name:     "Missing number",
			password: "NoNumberHere!",
			expected: []string{"Missing number."},
		},
		{
			name:     "Missing special",
			password: "NoSpecialChar123",
			expected: []string{"Missing special character."},
		},
		{
			name:     "Valid strong",
			password: "ThisIsAStrong!@#Password99",
			expected: []string{},
		},
		{
			name:     "Pwned",
			password: "Password123!@#45",
			// It might be pwned. This requires network access, we just verify it runs.
			// Depending on network it might return "Found in breach database (HIBP)."
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feedback := checkPasswordStrength(tt.password)
			if tt.name == "Pwned" {
				return // skip strict assertions for network calls in simple test
			}
			
			if tt.name == "Valid strong" && len(feedback) != 0 {
				t.Errorf("expected empty feedback, got %v", feedback)
			}
			
			if len(tt.expected) > 0 {
				found := false
				for _, f := range feedback {
					if strings.Contains(f, tt.expected[0]) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected feedback to contain %q, got %v", tt.expected[0], feedback)
				}
			}
		})
	}
}

func TestGeneratePassword(t *testing.T) {
	t.Run("Default settings", func(t *testing.T) {
		pwd := generatePassword(16, false)
		if len(pwd) < 16 || len(pwd) > 24 {
			t.Errorf("expected length between 16 and 24, got %d", len(pwd))
		}
		if !containsRuneFrom(pwd, upperChars) {
			t.Error("missing uppercase")
		}
		if !containsRuneFrom(pwd, lowerChars) {
			t.Error("missing lowercase")
		}
		if !containsRuneFrom(pwd, numberChars) {
			t.Error("missing number")
		}
		if !containsRuneFrom(pwd, specialChars) {
			t.Error("missing special character")
		}
	})

	t.Run("Custom length", func(t *testing.T) {
		pwd := generatePassword(20, false)
		if len(pwd) != 20 {
			t.Errorf("expected length 20, got %d", len(pwd))
		}
	})

	t.Run("Enforced minimum length", func(t *testing.T) {
		pwd := generatePassword(10, false)
		if len(pwd) != 16 {
			t.Errorf("expected length 16, got %d", len(pwd))
		}
	})

	t.Run("Enforced maximum length", func(t *testing.T) {
		pwd := generatePassword(30, false)
		if len(pwd) != 24 {
			t.Errorf("expected length 24, got %d", len(pwd))
		}
	})

	t.Run("No symbols", func(t *testing.T) {
		pwd := generatePassword(16, true)
		if containsRuneFrom(pwd, specialChars) {
			t.Error("expected no symbols, but found some")
		}
	})
}

func containsRuneFrom(s, chars string) bool {
	for _, c := range s {
		if strings.ContainsRune(chars, c) {
			return true
		}
	}
	return false
}
