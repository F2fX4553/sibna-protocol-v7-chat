# 🪐 Sibna Messenger • V11 Elite

![Messenger Preview](https://img.shields.io/badge/Version-11.0.0_Elite-blueviolet?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Ultra_Stable-success?style=for-the-badge)
![Encryption](https://img.shields.io/badge/Security-P2P_Encrypted-orange?style=for-the-badge)

**Sibna Messenger** is a state-of-the-art communication ecosystem designed for the modern age. It combines high-performance P2P message delivery with a premium, glassmorphic UI/UX and a professional-grade media engine.

---

## 🚀 Key Highlights

### 📞 Professional Calling Engine
*   **Segregated Channels**: Dedicated logical flows for **Crystal-Clear Voice** and **Ultra-HD Video** calls.
*   **Media Toggles**: Real-time interactive controls for Muting and Camera Switching with dynamic iconography.
*   **Messenger-Style History**: Automatic event logging that records every call session and its duration directly in the chat timeline.
*   **Hardware Sync**: Advanced resource management that ensures your camera and microphone are strictly released upon session termination.

### 💬 Intelligent Messaging
*   **Zero-Flicker Rendering**: A custom state-comparison engine that ensures perfectly smooth updates without UI refreshes.
*   **Rich Media Engine**: Native support for image previews, file attachments, and complex JSON-based rich messages.
*   **Chronological Integrity**: Precision Unix timestamps ensure that your conversation history is always perfectly ordered, from the first hello to the last goodbye.

### 🎨 Elite Visual Design
*   **Glassmorphism**: A deep, immersive dark theme with frosted-glass overlays and vibrant HSL gradients.
*   **Hex-Node Visuals**: Signature hexagonal design for avatars and video feeds, providing a futuristic and distinguished identity.
*   **System Soundscape**: Premium auditory feedback for every interaction, from dialing tones to new message whispers.

---

## 🛠️ Technical Specification

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Python 3.10+ / Flask | Secure Node Gateway |
| **Protocol** | custom Sibna_SDK | P2P Signaling & Handshaking |
| **Frontend** | Vanilla JS (ES6+) | Real-time UI & Media Engine |
| **Styling** | Modern CSS3 | Glassmorphic Design System |
| **Database** | SQLite3 Nodes | Local Encrypted Storage |

---

## 📦 Project Architecture

```bash
chat_app/
├── app.py              # Main application gateway
├── README.md           # Documentation
├── sibna_sdk/          # Core protocol logic
│   ├── client.py       # Message processing worker
│   └── database.py     # Secure storage manager
├── static/
│   ├── css/style.css   # Elite design system
│   ├── js/chat.js      # Critical signaling & media logic
│   └── audio/          # System sounds (External assets)
└── templates/
    └── index.html      # Structural foundation
```

---

## � Getting Started

### 1. Requirements
Ensure you have Python installed. The only dependency is Flask.
```bash
pip install flask
```

### 2. Execution
Launch your local Sibna node:
```bash
python app.py
```

### 3. Verification
To experience the full multi-user sync:
- Open Two browser tabs.
- Login as `Alice` and `Bob`.
- **Chat**: Observe real-time delivery with image/file support.
- **Call**: Initiate a Video call, Accept it, and observe the MM:SS timer and media toggles.

---
*Built for the future of secure, beautiful communication.*
