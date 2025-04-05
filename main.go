package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/ParasJain0307/Encryption-With-Go/filecrypt"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandler()
	case "decrypt":
		decryptHandler()
	default:
		fmt.Println("[ERROR] Unknown command:", command)
		fmt.Println("Use `help` to see available commands.")
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("File Encryption Tool - CLI")
	fmt.Println("Simple AES encryption/decryption for your files.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  go run . <command> <file-path>")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  encrypt     Encrypts a file with a password")
	fmt.Println("  decrypt     Decrypts a file using the same password")
	fmt.Println("  help        Display this help message")
	fmt.Println("")
}

func encryptHandler() {
	if len(os.Args) < 3 {
		fmt.Println("[ERROR] Missing file path. Use `help` for usage.")
		os.Exit(1)
	}

	file := os.Args[2]
	if !validateFile(file) {
		fmt.Println("[ERROR] File not found:", file)
		os.Exit(1)
	}

	password := getPassword()

	fmt.Println("[INFO] Encrypting...")
	filecrypt.Encrypt(file, password)
	fmt.Println("[INFO] File successfully encrypted.")
}

func decryptHandler() {
	if len(os.Args) < 3 {
		fmt.Println("[ERROR] Missing file path. Use `help` for usage.")
		os.Exit(1)
	}

	file := os.Args[2]
	if !validateFile(file) {
		fmt.Println("[ERROR] File not found:", file)
		os.Exit(1)
	}

	fmt.Print("Enter password: ")
	password, _ := term.ReadPassword(0)

	fmt.Println("\n[INFO] Decrypting...")
	filecrypt.Decrypt(file, password)
	fmt.Println("[INFO] File successfully decrypted.")
}

func getPassword() []byte {
	fmt.Print("Enter password: ")
	pwd1, _ := term.ReadPassword(0)

	fmt.Print("\nConfirm password: ")
	pwd2, _ := term.ReadPassword(0)

	if !bytes.Equal(pwd1, pwd2) {
		fmt.Println("\n[ERROR] Passwords do not match. Try again.")
		return getPassword()
	}

	return pwd1
}

func validateFile(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}
