# Sibna Messenger | Ultra-Secure Communication Suite 🚀

Welcome to **Sibna Messenger V10**, a professional-grade, high-end communication application built with a focus on privacy, aesthetics, and a seamless user experience. This application leverages the **Sibna Protocol** to provide cross-user messaging and interactive calling.

## ✨ Core Features

### 🎬 Professional Calling Suite
- **Segregated Call Types**: Distinct flows for **Voice Calls** (Audio-only) and **Video Calls** (Full Media).
- **Interactive Controls**: Messenger-grade Mute/Unmute and Camera Toggle functionality.
- **Messenger-Style Logs**: Every call is automatically logged in the chat history with its exact duration (e.g., `Video call ended • 00:45`).
- **Real-Time Handshaking**: Robust signaling prevents "re-calling loops" and ensures multi-window synchronization.
- **Hardware Management**: Automatic release of camera and microphone resources upon call termination.

### 💬 Premium Chat Experience
- **Real P2P Sync**: Messages are delivered directly to the recipient's secure database on disk.
- **Rich Media Sharing**: Support for image previews, file attachments (PDF, Text, etc.), and immersive system messages.
- **Flicker-Free UI**: Advanced state-detection rendering prevents UI flickering during background polling.
- **Chronological Sorting**: Precision Unix timestamps ensure messages are always in the perfect order.

### 💎 Elite Design System
- **Glassmorphism**: A modern, sleek dark theme with translucent overlays.
- **Hexagon Visuals**: Unique hexagonal avatars and video containers for a distinguished, premium feel.
- **Sound Design**: Immersive auditory feedback for Dialing, Connecting, and New Messages.
- **Lucide Iconography**: High-quality, vector-based icons throughout the interface.

---

## 🛠️ Technical Architecture

- **Backend**: Flask (Python) with a custom `sibna_sdk`.
- **Frontend**: Vanilla HTML5, CSS3 (Custom Variables), and Modern JavaScript (ES6+).
- **Storage**: Local SQLite encryption nodes (`*_storage.db`)—no central server database needed for messages.
- **Media**: `getUserMedia` API for real-time local and simulated remote feeds.

---

## 🚀 Getting Started

1. **Install Dependencies**:
   ```bash
   pip install flask
   ```
2. **Launch the Node**:
   ```bash
   python app.py
   ```
3. **Multi-User Testing**:
   - Open two browser tabs at `http://127.0.0.1:5000`.
   - Login with different IDs (e.g., `User_A` and `User_B`).
   - Experience real-time messaging and the dual-stream calling simulator.

---

## 📂 Project Structure
- `app.py`: The secure Flask application gateway.
- `sibna_sdk/`: The core communication protocol logic.
- `static/`:
  - `css/style.css`: The high-end design system.
  - `js/chat.js`: The complex signaling and media engine.
- `templates/index.html`: The structural foundation of the UI.

---
*Created with excellence for the Sibna Protocol.*
