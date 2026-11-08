# Nexus directors' view

Password-protected summary page for the directors of Nexus Property Developers (Pvt) Ltd.

- `index.html`: the page. It asks for a password and decrypts `data.enc.json` in the browser.
- `data.enc.json`: the encrypted figures (AES-256-GCM, key from PBKDF2-SHA256). It is unreadable without the password.
- `build.py`: encrypts the summary record from the Nexus Finance Desk app. It runs each morning.
