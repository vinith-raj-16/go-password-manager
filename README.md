# Go Password Manager

A secure, command-line password generator and strength checker written in Go. It allows you to generate strong, cryptographically secure passwords and can optionally send them to a Slack workspace via webhooks. It also features a `check` subcommand that evaluates password strength and checks it against known data breaches via the HIBP (Have I Been Pwned) API.

## Features

- **Generate Passwords:** Generate secure passwords with configurable length and optional symbol exclusion.
- **Password Strength Checker:** Analyzes passwords for length, character variety (uppercase, lowercase, numbers, symbols).
- **Breach Detection:** Checks the HIBP (Have I Been Pwned) database (safely using k-Anonymity) to see if a password has been compromised.
- **Slack Integration:** Send newly generated passwords directly to a Slack channel via a webhook.

## Installation

Ensure you have [Go installed](https://golang.org/dl/). 

Clone the repository:
```bash
git clone https://github.com/vinith-raj-16/go-password-manager.git
cd go-password-manager
```

## Setup (Optional: Slack Webhook)

If you want to use the `--slack` flag to send passwords to Slack, you need to set up your environment variables:

1. Copy the example `.env` file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and replace the placeholder with your actual Slack Webhook URL:
   ```env
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK_URL
   ```

## Usage

You can run the application using `go run main.go` followed by a subcommand.

### Generating Passwords

```bash
go run main.go generate [flags]
```

**Flags:**
- `--length <int>`: Length of the password (16-24, default is 16).
- `--no-symbols`: Exclude special characters.
- `--slack`: Send the generated password to the configured Slack webhook.

**Examples:**
```bash
# Generate a standard 16-character password
go run main.go generate

# Generate a 20-character password without symbols
go run main.go generate --length 20 --no-symbols

# Generate a password and send it to Slack
go run main.go generate --slack
```

### Checking Password Strength

```bash
go run main.go check <password>
```

**Example:**
```bash
go run main.go check mysecretpassword
```
