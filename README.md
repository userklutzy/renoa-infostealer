



# RENOA — Windows Infostealer Research & Detection Lab

A controlled proof-of-concept for studying browser credential storage, Windows DPAPI/CNG, and defensive detection techniques.

![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Type](https://img.shields.io/badge/type-Research%20PoC-red)
![Purpose](https://img.shields.io/badge/purpose-Educational-blue)
![Environment](https://img.shields.io/badge/environment-Isolated%20VM-orange)

> ⚠️ **Do not test on a personal PC.** Use an isolated virtual machine or sandbox. The screenshots in this repository were taken inside a VM with test accounts and non-sensitive data.

> ⚠️ **Passwords may not decrypt on some Chrome versions.** Chrome v20 App-Bound Encryption changes frequently and some builds require SYSTEM context or additional key material.

---

## Disclaimer & Educational Purpose

This repository contains a Proof of Concept (PoC) developed strictly for educational, research, and detection engineering purposes. It is designed to demonstrate how specific Windows security APIs (DPAPI/CNG) interact with browser storage mechanisms.

Unauthorized use against systems you do not own or have explicit permission to test is strictly prohibited.

RENOA is a Windows-based security research project created to help security researchers, developers, and students understand how infostealer malware operates, how browser data may be targeted, and how defensive detection techniques can be developed.

---

## Authorized Environments

Use this project only in environments where you have full ownership or explicit permission:

- 🖥️ Isolated virtual machines
- 🧪 Malware-analysis laboratories
- 🔬 Personal security-research environments
- 🎯 CTF environments
- 🛡️ Authorized penetration-testing environments
- 💻 Personal test systems

---

## Research & Educational Purpose

This repository can be used to study:

- Malware analysis
- Reverse engineering
- Infostealer behavior
- Browser-data security
- Detection engineering
- Incident-response techniques
- Defensive security research
- Malware-analysis methodologies

The purpose of this project is to help researchers understand how these threats work so they can be analyzed, detected, and defended against.

---

## Features

- Browser credential extraction from Chromium-based browsers and Firefox
- Cookie extraction and Netscape export
- Credit card and CVC extraction
- Autofill and history extraction
- Discord token grabbing
- Chrome v20 App-Bound Encryption handling (DPAPI + CNG + AES/ChaCha20/XOR)
- Screenshot and system info collection
- In-memory ZIP packaging
- Discord webhook upload for lab verification

---

## Supported Browsers

- Chrome
- Chrome Beta
- Edge
- Brave
- Vivaldi
- Chromium
- Opera
- Opera GX
- Firefox

---

## How Chrome v20 Works

Chrome v20 refers to App-Bound Encryption introduced around Chrome 127. It changed how the master key is stored in the `Local State` file.

**Old scheme (v10):**

- The encrypted key is a base64 string starting with `DPAPI`.
- Strip `DPAPI`, call `CryptUnprotectData`, get the 32-byte AES key.
- This key decrypts passwords, cookies, and cards with AES-256-GCM.

**New scheme (v20):**

- The app-bound encrypted key is a base64 string starting with `APPB`.
- Strip `APPB`, then the blob must be decrypted twice under the SYSTEM token.
- After the two DPAPI passes, the result is either a raw 32-byte AES key, or a structured blob with a flag byte.
- Flag 1: AES-GCM with a hardcoded AES key.
- Flag 2: ChaCha20-Poly1305 with a hardcoded ChaCha20 key.
- Flag 3: encrypted AES key decrypted via CNG, then XORed, then used as AES-GCM key.

This project handles all three flags.

---

## Modification

You are free to study, modify, improve, refactor, and extend the project for legitimate research and educational purposes.

Any modified or redistributed version should retain appropriate attribution and the original security disclaimer.

---

## No Warranty / No Liability

This software is provided "AS IS", without warranties of any kind.

The author assumes no responsibility or liability whatsoever for any misuse, damage, data loss, unauthorized access, privacy violation, security incident, legal consequence, or other harm resulting from the use, modification, distribution, or deployment of this project.

You are solely responsible for your actions and for ensuring that your use of this software complies with all applicable laws, regulations, and authorization requirements.

By using, modifying, or distributing this project, you acknowledge and accept these terms.

---

## Security Notice

Do not run this software on computers, accounts, or environments containing data that you do not have permission to access.

For safe research, use an isolated virtual machine or dedicated laboratory environment with test accounts and non-sensitive data.

---

## Intended Audience

This project may be useful for:

- Security researchers
- Malware analysts
- Reverse engineers
- Cybersecurity students
- Detection engineers
- Blue-team researchers
- Developers studying malware behavior

---

## License

See the `LICENSE` file for the applicable license terms.

---

## Final Notice

Educational use only. Authorized environments only.

Do not use this project for unauthorized access, credential theft, data theft, or any other illegal activity.

Use responsibly. Use only where you have explicit authorization.
