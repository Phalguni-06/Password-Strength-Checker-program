# 🔐 Password Strength Checker

A professional Python-based password security analyzer designed to evaluate password strength using multiple security indicators such as **Shannon entropy, password-pattern analysis, crack-time estimation, common/breached-password detection, and NIST 800-63B guideline checks**.

The project also includes a **cryptographically secure password generator** using Python's `secrets` module. It can be used interactively from the terminal or imported into other Python programs.

---

## 📌 Project Overview

Weak and predictable passwords are one of the most common causes of account compromise. This project provides a practical way to understand how different characteristics of a password affect its security.

The Password Strength Checker analyzes a password and produces a detailed security assessment rather than relying only on simple rules such as minimum length.

### Key analysis areas

* Password length
* Character-set diversity
* Shannon entropy
* Estimated crack time
* Common-password detection
* Keyboard-pattern detection
* Sequential-character detection
* Repeated-character/pattern detection
* Date-pattern detection
* Leet-speak pattern detection
* Common suffix detection
* NIST 800-63B guideline checks
* Security recommendations
* Secure password generation

---

## ✨ Features

### 🧠 Shannon Entropy

Calculates password entropy to estimate the unpredictability of the password.

### ⏱️ Crack-Time Estimation

Provides an estimated time required to guess a password based on configured guessing-rate assumptions.

> Crack-time values are educational estimates and should not be treated as exact real-world attack predictions.

### 🚨 Common / Breached Password Detection

Checks passwords against a local common-password dictionary.

> This is a **local dictionary check**, not a live lookup against Have I Been Pwned or another external breach database. A password that is not found locally should not automatically be considered safe.

### 🔎 Advanced Pattern Detection

The checker looks for predictable patterns including:

* Keyboard sequences
* Number and character sequences
* Repeated characters
* Repeated patterns
* Dates
* Leet-speak substitutions
* Common suffixes

### 📋 NIST 800-63B Checks

Evaluates password characteristics against the project's implemented NIST 800-63B-oriented checks and provides recommendations.

### 💡 Security Recommendations

Provides actionable feedback to help improve weak passwords.

### 🔑 Secure Password Generation

Generates strong passwords using Python's `secrets` module for cryptographically secure randomness.

### 🖥️ Interactive CLI

The program provides a simple terminal-based interface:

```text
1. Check a password
2. Generate a strong password
3. Exit
```

The password is masked in the analysis report to avoid unnecessarily displaying it on screen.

---

## 🛠️ Technologies Used

* **Python 3.8+**
* Python Standard Library
* `secrets`
* `math`
* `re`
* Terminal / Command Line Interface

No third-party packages are required.

---

## 📂 Project Structure

```text
Password-Strength-Checker-program/
│
├── password-strength-checker-github/
│   ├── password_strength_checker.py
│   ├── README.md
│   ├── requirements.txt
│   ├── LICENSE
│   └── .github/
│       └── workflows/
│           └── python-check.yml
│
└── README.md
```

The repository currently contains the main project folder, source code, README, license, requirements file, and GitHub Actions workflow.

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Phalguni-06/Password-Strength-Checker-program.git
```

### 2. Open the project directory

```bash
cd Password-Strength-Checker-program
```

### 3. Run the program

```bash
python password-strength-checker-github/password_strength_checker.py
```

Or, from inside the project directory:

```bash
python password_strength_checker.py
```

---

## ▶️ Usage

After starting the program, select an option from the menu.

### Check Password

```text
1. Check a password
```

Enter a password and the program analyzes its security characteristics and displays a detailed assessment.

### Generate Strong Password

```text
2. Generate a strong password
```

The application generates a secure password using Python's `secrets` module.

### Exit

```text
3. Exit
```

---

## 🐍 Use as a Python Module

The checker can also be imported into another Python application.

```python
from password_strength_checker import check_password_strength

result = check_password_strength("ExamplePassword123!")

print("Strength:", result["strength_label"])
print("Score:", result["score"])
print("Entropy:", result["entropy"])
```

The project exposes the password-strength checking functionality for programmatic use.

---

## 📊 Example Analysis

A password assessment can provide information such as:

```text
Password Strength: Strong
Score: ...
Entropy: ...
Estimated Crack Time: ...
Pattern Warnings: ...
Recommendations: ...
```

The exact result depends on the password being tested and the analysis performed by the program.

---

## 🔒 Security Considerations

This project is primarily intended for **cybersecurity education, password-awareness training, experimentation, and learning**.

### Important

* Do not use real production passwords when experimenting with the program.
* Do not assume that a password is safe simply because it is not found in the project's local dictionary.
* Crack-time values are estimates based on assumptions in the program.
* Passwords should never be stored in plaintext.
* For real-world systems, use an appropriate password-storage mechanism and secure authentication architecture.

The repository specifically notes that its breach detection is a local common-password check rather than a complete external breach database lookup.

---

## 🎯 Learning Objectives

This project helps demonstrate practical cybersecurity concepts such as:

* Password security
* Entropy
* Brute-force attacks
* Dictionary attacks
* Password pattern recognition
* Secure random password generation
* Security policy evaluation
* NIST-oriented password guidance
* Python security programming

---

## ✅ Why This Project?

The project goes beyond a basic "strong/weak" password checker by combining several indicators into one security assessment.

It is suitable as a:

* Cybersecurity mini project
* Python security project
* College academic project
* Portfolio project
* GitHub project
* Cybersecurity learning tool

---

## 🧪 Testing

The repository includes a GitHub Actions workflow for automatically checking the Python project.

You can also verify that the Python file compiles successfully:

```bash
python -m py_compile password_strength_checker.py
```

---

## 📜 License

This project is available under the **MIT License**.

---

## 👩‍💻 Author

**Phalguni**

GitHub: [@Phalguni-06](https://github.com/Phalguni-06)

Repository: [Password-Strength-Checker-program](https://github.com/Phalguni-06/Password-Strength-Checker-program)

---

## ⭐ Support

If you find this project useful for learning Python or cybersecurity, consider giving the repository a ⭐ on GitHub.
