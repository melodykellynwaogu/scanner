# Contributing Guidelines

Thank you for your interest in contributing to the SOC Web Recon & Hardening Dashboard! We welcome contributions that improve security detection, UI/UX, and performance.

---

## Development & Setup Instructions

To keep the main branch stable and secure, direct pushes to `main` are restricted. Please follow the instructions below to set up your environment and submit a Pull Request.

### 1. Prerequisites (Nmap Installation)

This application requires the `nmap` engine installed on your system.

- **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt update && sudo apt install nmap -y

```

* **macOS (using Homebrew):**
```bash
brew install nmap

```


* **Windows:**
Download and run the installer from the official page: [Nmap Official Downloads](https://nmap.org/download.html). Ensure Nmap is added to your system `PATH`.

---

### 2. Fork & Clone

1. Click **Fork** at the top right of this repository to create your copy.
2. Clone your forked repository locally:
```bash
git clone [https://github.com/YOUR_USERNAME/scanner.git](https://github.com/YOUR_USERNAME/scanner.git)
cd scanner

```



---

### 3. Virtual Environment Setup

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

#### Windows (Command Prompt / PowerShell)

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

```

---

### 4. Running the Project

Start the local development server:

```bash
uvicorn app:app --reload

```

Open your browser and navigate to `http://127.0.0.1:8000`.

---

## Submitting Changes

1. **Create a Feature Branch:**
```bash
git checkout -b feature/your-feature-name

```


2. **Make & Test Changes:** Ensure the scanner runs locally without errors.
3. **Commit & Push:**
```bash
git add .
git commit -m "Feat: description of your change"
git push origin feature/your-feature-name

```


4. **Open a Pull Request:** Go to the original repository on GitHub and click **Compare & pull request**.

---

## Security Policy

All Pull Requests undergo manual code review before merging. Submissions containing the following will be rejected:

* Unvalidated user inputs vulnerable to command execution.
* Malicious or obfuscated code blocks.
* External tracking or unnecessary third-party dependencies.

---