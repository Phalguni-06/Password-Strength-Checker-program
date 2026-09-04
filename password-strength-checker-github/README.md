# Password Strength Checker — Professional Edition

A Python command-line password security analyzer based on the supplied project.

## Features

- Shannon entropy calculation
- Estimated crack time
- Local common/breached-password detection
- Keyboard, sequence, repeat, date, leet-speak, and suffix pattern detection
- NIST 800-63B guideline checks
- Detailed feedback and security recommendations
- Cryptographically secure password generation with `secrets`
- Interactive terminal menu
- Works as an importable Python module

## Requirements

- Python 3.8+
- No third-party packages required

## Run

```bash
python password_strength_checker.py
```

## Example

Choose:

1. Check a password
2. Generate a strong password
3. Exit

The checker masks the password in the analysis report and displays a detailed security assessment.

## Import as a module

```python
from password_strength_checker import check_password_strength

result = check_password_strength("ExamplePassword123!")
print(result["strength_label"])
print(result["score"])
print(result["entropy"])
```

## Security note

The breach check in this project is a **local common-password dictionary check**, not a live lookup against the complete Have I Been Pwned or another external breach database. A password not found locally should not be assumed to be safe.

Crack-time values are estimates based on the configured guess rates in the source code and should be treated as rough educational estimates.

## Project structure

```text
password-strength-checker/
├── password_strength_checker.py
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
└── .github/
    └── workflows/
        └── python-check.yml
```

## GitHub upload

```bash
git init
git add .
git commit -m "Initial password strength checker"
git branch -M main
git remote add origin YOUR_GITHUB_REPOSITORY_URL
git push -u origin main
```

## License

MIT License
