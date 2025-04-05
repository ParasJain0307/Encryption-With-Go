# 🔐 File Encryption CLI Tool (Go)

A simple and secure file encryption & decryption CLI tool built in Go. It uses **AES-256-GCM** encryption with **PBKDF2** for key derivation from a password.

---

## 📦 Features

- ✅ AES-GCM encryption for confidentiality and integrity  
- 🔑 Password-based key derivation (PBKDF2 with salt/nonce)  
- 🛡️ Prevents double encryption and double decryption  
- 🖥️ Clean CLI interface with helpful log output  
- 🔄 Cross-platform compatible  

---

## 📁 Project Structure

```bash
Encryption-With-Go/
├── filecrypt/
│   └── filecrypt.go       # Encryption/Decryption logic
├── main.go                # CLI interface
└── README.md              # Documentation

🚀 Getting Started
✅ Prerequisites
Go installed (version 1.18 or higher)

🔧 Build the Tool
git clone https://github.com/your-username/Encryption-With-Go.git
cd Encryption-With-Go
go build -o filecrypt-cli


🛠️ Usage
🔒 Encrypt a file
./filecrypt-cli encrypt /path/to/your/file.txt

You will be prompted to enter and confirm a password.

🔓 Decrypt a file
./filecrypt-cli decrypt /path/to/your/file.txt
You will be prompted to enter the password.



🧪 Example
$ ./filecrypt-cli encrypt secret.txt
Enter Password:
Confirm Password:
[INFO] Encrypting...
[INFO] File successfully encrypted.

$ ./filecrypt-cli decrypt secret.txt
Enter Password:
[INFO] Decrypting...
[INFO] File successfully decrypted.


🔐 How It Works
🔄 Encryption Flow

graph TD
    A[Original File] --> B[Read File]
    B --> C[Generate Nonce]
    C --> D[Derive Key (PBKDF2)]
    D --> E[AES-GCM Seal]
    E --> F[Append Nonce to Ciphertext]
    F --> G[Overwrite File with Ciphertext]


🔓 Decryption Flow
graph TD
    A[Encrypted File] --> B[Read File]
    B --> C[Extract Nonce]
    C --> D[Derive Key (PBKDF2)]
    D --> E[AES-GCM Open]
    E --> F[Write Plaintext Back to File]


⚠️ Notes
    Files are overwritten in-place (no backups created).

    Detects and blocks:

    Re-encryption of already encrypted files

    Re-decryption of already decrypted files

    Incorrect password causes decryption failure (no data leak).

    PBKDF2 with SHA-1 and 4096 iterations is used for key derivation.


🧰 Built With
    
    Go

    AES-GCM

    PBKDF2

    golang.org/x/crypto

🛡️ Security Disclaimer
    This tool is intended for educational and small-scale secure usage. It uses modern cryptography, but has not undergone formal security audits. Use with caution in critical production systems.

📃 License
This project is licensed under the MIT License.



