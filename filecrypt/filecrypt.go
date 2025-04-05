package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// Encrypt encrypts the given file with the provided password.
// It avoids double-encryption by attempting decryption first.
func Encrypt(filePath string, password []byte) {
	logInfo("Starting encryption for file:", filePath)

	// Open source file
	srcFile, err := os.Open(filePath)
	if err != nil {
		logError("Failed to open file:", err)
		panic(err)
	}
	defer srcFile.Close()

	// Read file content
	plaintext, err := io.ReadAll(srcFile)
	if err != nil {
		logError("Failed to read file:", err)
		panic(err)
	}

	// Check if already encrypted
	if isAlreadyEncrypted(plaintext, password) {
		logInfo("File appears to be already encrypted. Skipping encryption.")
		return
	}

	// Generate a 12-byte nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logError("Failed to generate nonce:", err)
		panic(err)
	}

	// Derive AES key using PBKDF2
	key := pbkdf2.Key(password, nonce, 4096, 32, sha1.New)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		logError("Failed to create AES cipher:", err)
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		logError("Failed to create AES-GCM:", err)
		panic(err)
	}

	// Encrypt data and append nonce to ciphertext
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(ciphertext, nonce...)

	// Overwrite original file
	dstFile, err := os.Create(filePath)
	if err != nil {
		logError("Failed to create encrypted file:", err)
		panic(err)
	}
	defer dstFile.Close()

	_, err = dstFile.Write(ciphertext)
	if err != nil {
		logError("Failed to write encrypted content:", err)
		panic(err)
	}

	logInfo("File successfully encrypted.")
}

// Decrypt decrypts the given file with the provided password.
// If the file is not encrypted or already decrypted, it skips cleanly.
func Decrypt(filePath string, password []byte) {
	logInfo("Starting decryption for file:", filePath)

	// Open source file
	srcFile, err := os.Open(filePath)
	if err != nil {
		logError("Failed to open file:", err)
		panic(err)
	}
	defer srcFile.Close()

	// Read file content
	ciphertext, err := io.ReadAll(srcFile)
	if err != nil {
		logError("Failed to read file:", err)
		panic(err)
	}

	// Ensure ciphertext is long enough to include nonce
	if len(ciphertext) < 12 {
		logError("File is too short to be encrypted.")
		fmt.Println("[WARN] File may already be decrypted or corrupt.")
		return
	}

	// Extract nonce from the end of the file
	nonce := ciphertext[len(ciphertext)-12:]
	encryptedData := ciphertext[:len(ciphertext)-12]

	// Derive key using PBKDF2
	key := pbkdf2.Key(password, nonce, 4096, 32, sha1.New)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		logError("Failed to create AES cipher:", err)
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		logError("Failed to create AES-GCM:", err)
		panic(err)
	}

	// Attempt decryption
	plaintext, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		logError("Decryption failed:", err)
		fmt.Println("[WARN] File might already be decrypted or password is incorrect.")
		return
	}

	// Overwrite file with decrypted content
	dstFile, err := os.Create(filePath)
	if err != nil {
		logError("Failed to create decrypted file:", err)
		panic(err)
	}
	defer dstFile.Close()

	_, err = dstFile.Write(plaintext)
	if err != nil {
		logError("Failed to write decrypted content:", err)
		panic(err)
	}

	logInfo("File successfully decrypted.")
}

// isAlreadyEncrypted attempts decryption as a heuristic to detect if a file is already encrypted.
func isAlreadyEncrypted(data []byte, password []byte) bool {
	if len(data) < 12 {
		return false
	}
	nonce := data[len(data)-12:]
	encrypted := data[:len(data)-12]

	key := pbkdf2.Key(password, nonce, 4096, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}

	// If decryption succeeds, it's already encrypted
	_, err = aesgcm.Open(nil, nonce, encrypted, nil)
	return err == nil
}

// logInfo logs informational messages
func logInfo(msg ...any) {
	fmt.Println("[INFO]", fmt.Sprint(msg...))
}

// logError logs error messages
func logError(msg ...any) {
	fmt.Println("[ERROR]", fmt.Sprint(msg...))
}
