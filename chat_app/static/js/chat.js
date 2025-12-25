document.addEventListener('DOMContentLoaded', () => {
    // V7 Application State
    const state = {
        currentUser: null,
        activeRecipient: null,
        selectedFiles: [],
        pollingInterval: null,
        contacts: [
            { id: 'Protocol_Service', name: 'Protocol Service' }
        ],
        isCommActive: false,
        ringtone: new Audio('https://assets.mixkit.co/active_storage/sfx/1359/1359-preview.mp3'),
        msgSound: new Audio('https://assets.mixkit.co/active_storage/sfx/2358/2358-preview.mp3'),
        beepSound: new Audio('https://assets.mixkit.co/active_storage/sfx/1351/1351-preview.mp3'),
        lastMsgCount: 0,
        lastRenderedJson: "",
        processedSignals: new Set(),
        localStream: null,
        callTimerInterval: null,
        callStartTime: null,
        isMuted: false,
        isCamOff: false,
        activeCallType: 'Video'
    };

    state.ringtone.loop = true;

    // UI Components
    const ui = {
        loginModal: document.getElementById('login-modal'),
        appUi: document.getElementById('app-ui'),
        loginBtn: document.getElementById('login-btn'),
        usernameInp: document.getElementById('username-input'),
        myName: document.getElementById('my-name'),
        myAvatar: document.getElementById('my-avatar'),
        userSearchInp: document.getElementById('user-search-input'),
        contactsList: document.getElementById('contacts-list'),
        msgContainer: document.getElementById('messages-container'),
        msgInput: document.getElementById('message-input'),
        sendBtn: document.getElementById('send-btn'),
        chatTargetName: document.getElementById('chat-recipient-name'),
        chatTargetAvatar: document.getElementById('chat-recipient-avatar'),
        attachBtn: document.getElementById('attach-btn'),
        fileInp: document.getElementById('file-input'),
        filePreviewBox: document.getElementById('file-preview-container'),

        // Communication UI
        commOverlay: document.getElementById('comm-overlay'),
        commAvatar: document.getElementById('comm-avatar'),
        commName: document.getElementById('comm-name'),
        commStatus: document.getElementById('comm-status'),
        callTimer: document.getElementById('call-timer'),
        callBtn: document.getElementById('call-btn-v3'),
        videoBtn: document.getElementById('video-btn-v3'),
        endCallBtn: document.getElementById('end-call-btn'),
        acceptCallBtn: document.getElementById('accept-call-btn'),
        localVideo: document.getElementById('local-video'),
        remoteVideo: document.getElementById('remote-video'),
        muteBtn: document.getElementById('mute-btn'),
        toggleCamBtn: document.getElementById('toggle-cam-btn')
    };

    // --- 1. Authentication ---
    ui.loginBtn.addEventListener('click', async () => {
        const userId = ui.usernameInp.value.trim().toLowerCase();
        if (!userId) return;
        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });
            if (res.ok) {
                state.currentUser = userId;
                ui.myName.textContent = userId;
                ui.myAvatar.textContent = userId[0].toUpperCase();
                ui.loginModal.classList.add('hidden');
                ui.appUi.classList.remove('hidden');
                renderContacts();
                startPolling();
                refreshIcons();
            }
        } catch (e) { console.error("Login failed", e); }
    });

    // --- 2. Discovery & Contacts ---
    ui.userSearchInp.addEventListener('input', debounce(async (e) => {
        const query = e.target.value.trim().toLowerCase();
        if (!query) return;
        try {
            const res = await fetch(`/api/search?q=${query}`, {
                headers: { 'X-User-ID': state.currentUser }
            });
            const data = await res.json();
            updateContacts(data.users);
        } catch (e) { console.error("Search failed"); }
    }, 400));

    function updateContacts(users) {
        users.forEach(u => {
            if (!state.contacts.find(c => c.id === u.id)) {
                state.contacts.unshift(u);
            }
        });
        renderContacts();
    }

    function renderContacts() {
        ui.contactsList.innerHTML = '';
        state.contacts.forEach(contact => {
            const card = document.createElement('div');
            card.className = `contact-card-v3 ${state.activeRecipient === contact.id ? 'active' : ''}`;
            card.innerHTML = `
                <div class="mini-avatar">${contact.id[0].toUpperCase()}</div>
                <div class="contact-meta">
                    <div class="contact-name">${contact.id}</div>
                    <div class="contact-last-msg">Active Node</div>
                </div>
            `;
            card.onclick = () => selectContact(contact.id);
            ui.contactsList.appendChild(card);
        });
    }

    function selectContact(id) {
        state.activeRecipient = id;
        ui.chatTargetName.textContent = id;
        ui.chatTargetAvatar.textContent = id[0].toUpperCase();
        state.lastRenderedJson = ""; // Force re-render on contact switch
        renderContacts();
        fetchMessages();
    }

    // --- 3. Message Logic ---
    ui.sendBtn.addEventListener('click', sendMessage);
    ui.msgInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    ui.msgInput.addEventListener('input', function () {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';
    });

    async function sendMessage() {
        const text = ui.msgInput.value.trim();
        const recipient = state.activeRecipient;
        if (!recipient) return;
        if (!text && state.selectedFiles.length === 0) return;
        let payload = text;
        if (state.selectedFiles.length > 0) {
            payload = JSON.stringify({
                type: 'rich_message',
                text: text,
                files: state.selectedFiles.map(f => ({
                    name: f.name, size: f.size, type: f.type, data: f.data
                }))
            });
        }
        try {
            const res = await fetch('/api/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-User-ID': state.currentUser
                },
                body: JSON.stringify({ recipient, message: payload })
            });
            if (res.ok) {
                ui.msgInput.value = '';
                ui.msgInput.style.height = 'auto';
                state.selectedFiles = [];
                renderFilePreviews();
                fetchMessages();
            }
        } catch (e) { console.error("Transmission failed"); }
    }

    // --- 4. File Handling ---
    ui.attachBtn.addEventListener('click', () => ui.fileInp.click());
    ui.fileInp.addEventListener('change', (e) => {
        const files = Array.from(e.target.files);
        files.forEach(file => {
            const reader = new FileReader();
            reader.onload = (ev) => {
                state.selectedFiles.push({
                    id: Date.now() + Math.random(),
                    name: file.name,
                    size: formatBytes(file.size),
                    type: file.type,
                    data: ev.target.result
                });
                renderFilePreviews();
            };
            reader.readAsDataURL(file);
        });
        ui.fileInp.value = '';
    });

    function renderFilePreviews() {
        if (state.selectedFiles.length === 0) {
            ui.filePreviewBox.classList.add('hidden');
            return;
        }
        ui.filePreviewBox.classList.remove('hidden');
        ui.filePreviewBox.innerHTML = '';
        state.selectedFiles.forEach(f => {
            const div = document.createElement('div');
            div.className = 'file-card-v3';
            if (f.type.startsWith('image/')) {
                div.innerHTML = `<img src="${f.data}">`;
            } else {
                div.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--primary)"><i data-lucide="file-text"></i></div>`;
            }
            const rm = document.createElement('div');
            rm.className = 'rm-v3';
            rm.innerHTML = '×';
            rm.onclick = () => {
                state.selectedFiles = state.selectedFiles.filter(item => item.id !== f.id);
                renderFilePreviews();
            };
            div.appendChild(rm);
            ui.filePreviewBox.appendChild(div);
        });
        refreshIcons();
    }

    // --- 5. Message Rendering & Signaling ---
    async function fetchMessages() {
        if (!state.currentUser) return;
        try {
            const res = await fetch('/api/messages', {
                headers: { 'X-User-ID': state.currentUser }
            });
            const data = await res.json();

            // Signaling detection
            data.messages.forEach(m => {
                if (m.type === 'received' && m.content.includes('"type":"call_signal"')) {
                    const signalId = `${m.user}_${m.timestamp}`;
                    if (state.processedSignals.has(signalId)) return;

                    try {
                        const signal = JSON.parse(m.content);
                        if (signal.subType === 'offer' && !state.isCommActive) {
                            handleIncomingCall(m.user, signal.callType);
                            state.processedSignals.add(signalId);
                        } else if (signal.subType === 'accept' && state.isCommActive) {
                            establishLiveCall();
                            state.processedSignals.add(signalId);
                        } else if (signal.subType === 'end') {
                            remoteEndCall();
                            state.processedSignals.add(signalId);
                        } else if (signal.subType === 'media_state') {
                            handleRemoteMediaChange(signal.mediaType, signal.enabled);
                            state.processedSignals.add(signalId);
                        }
                    } catch (e) { }
                }
            });

            // Auto-Discovery
            data.messages.forEach(m => {
                if (m.type === 'received' && !state.contacts.find(c => c.id === m.user)) {
                    state.contacts.push({ id: m.user, name: m.user });
                    renderContacts();
                }
            });

            // Flicker Prevention
            const currentJson = JSON.stringify(data.messages);
            if (currentJson !== state.lastRenderedJson) {
                if (data.messages.length > state.lastMsgCount) {
                    if (state.lastMsgCount > 0) state.msgSound.play().catch(() => { });
                    state.lastMsgCount = data.messages.length;
                }
                renderMessages(data.messages);
                state.lastRenderedJson = currentJson;
            }
        } catch (e) { console.warn("Polling..."); }
    }

    function renderMessages(messages) {
        const filtered = messages.filter(m => m.user === state.activeRecipient);
        ui.msgContainer.innerHTML = '';

        if (filtered.length === 0 && !state.activeRecipient) {
            ui.msgContainer.innerHTML = `
                <div class="welcome-view">
                    <div class="welcome-icon"><i data-lucide="message-circle"></i></div>
                    <h2>Secure Node Active</h2>
                    <p>Search for any user handle on the left to start an encrypted transmission.</p>
                </div>`;
            refreshIcons();
            return;
        }

        filtered.forEach(msg => {
            // Ignore call signals in UI (except system logs)
            if (msg.content.includes('"type":"call_signal"') && !msg.content.includes('"subType":"system_log"')) return;

            let isSystem = false;
            let bodyHtml = '';
            try {
                if (msg.content.includes('"subType":"system_log"')) {
                    const log = JSON.parse(msg.content);
                    bodyHtml = `<i data-lucide="info" style="width:14px;height:14px;vertical-align:middle;margin-right:6px"></i> ${log.content} • ${log.duration}`;
                    isSystem = true;
                } else if (msg.content.startsWith('{"type":"rich_message"')) {
                    const rich = JSON.parse(msg.content);
                    if (rich.text) bodyHtml += `<p>${rich.text}</p>`;
                    bodyHtml += `<div class="rich-v3-files">`;
                    rich.files.forEach(f => {
                        if (f.type.startsWith('image/')) {
                            bodyHtml += `<img src="${f.data}" class="rich-v3-img" onclick="window.open('${f.data}')">`;
                        } else {
                            bodyHtml += `
                                <a href="${f.data}" download="${f.name}" class="rich-v3-file">
                                    <i data-lucide="file"></i>
                                    <div class="rich-v3-meta"><div class="f-fn">${f.name}</div><div class="f-fs">${f.size}</div></div>
                                </a>`;
                        }
                    });
                    bodyHtml += `</div>`;
                } else {
                    bodyHtml = `<p>${msg.content}</p>`;
                }
            } catch (e) { bodyHtml = `<p>${msg.content}</p>`; }

            const wrap = document.createElement('div');
            wrap.className = `msg-wrapper-v3 ${isSystem ? 'system' : msg.type}`;

            const box = document.createElement('div');
            box.className = 'msg-box';

            const time = msg.timestamp ? new Date(msg.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Now';
            box.innerHTML = `${bodyHtml} ${isSystem ? '' : `<span class="msg-footer">${time}</span>`}`;
            wrap.appendChild(box);
            ui.msgContainer.appendChild(wrap);
        });

        ui.msgContainer.scrollTop = ui.msgContainer.scrollHeight;
        refreshIcons();
    }

    // --- 6. Communication UI (V8 ELITE) ---
    ui.callBtn.onclick = () => startCall('Voice Call');
    ui.videoBtn.onclick = () => startCall('Video Call');

    ui.endCallBtn.onclick = () => {
        // Send end signal
        if (state.activeRecipient) {
            const signal = JSON.stringify({ type: "call_signal", subType: "end" });
            fetch('/api/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-User-ID': state.currentUser },
                body: JSON.stringify({ recipient: state.activeRecipient, message: signal })
            });
        }
        terminateSession();
    };

    ui.acceptCallBtn.onclick = async () => {
        if (!state.activeRecipient) return;
        state.ringtone.pause();
        ui.acceptCallBtn.classList.add('hidden');

        // Reset toggles UI
        state.isMuted = false;
        state.isCamOff = false;
        ui.muteBtn.classList.remove('off');
        ui.toggleCamBtn.classList.remove('off');

        // Send accept signal
        const signal = JSON.stringify({ type: "call_signal", subType: "accept" });
        await fetch('/api/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-User-ID': state.currentUser },
            body: JSON.stringify({ recipient: state.activeRecipient, message: signal })
        });

        establishLiveCall();
    };

    ui.muteBtn.onclick = () => {
        if (!state.localStream) return;
        state.isMuted = !state.isMuted;
        const audioTrack = state.localStream.getAudioTracks()[0];
        if (audioTrack) audioTrack.enabled = !state.isMuted;

        ui.muteBtn.classList.toggle('off', state.isMuted);
        ui.muteBtn.innerHTML = state.isMuted ? '<i data-lucide="mic-off"></i>' : '<i data-lucide="mic"></i>';
        refreshIcons();
        sendMediaSignal('audio', !state.isMuted);
    };

    ui.toggleCamBtn.onclick = () => {
        if (!state.localStream) return;
        state.isCamOff = !state.isCamOff;
        const videoTrack = state.localStream.getVideoTracks()[0];
        if (videoTrack) videoTrack.enabled = !state.isCamOff;

        ui.toggleCamBtn.classList.toggle('off', state.isCamOff);
        ui.toggleCamBtn.innerHTML = state.isCamOff ? '<i data-lucide="video-off"></i>' : '<i data-lucide="video"></i>';
        refreshIcons();
        sendMediaSignal('video', !state.isCamOff);
    };

    function sendMediaSignal(type, enabled) {
        if (!state.activeRecipient) return;
        const signal = JSON.stringify({ type: "call_signal", subType: "media_state", mediaType: type, enabled: enabled });
        fetch('/api/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-User-ID': state.currentUser },
            body: JSON.stringify({ recipient: state.activeRecipient, message: signal })
        });
    }

    function handleRemoteMediaChange(type, enabled) {
        if (type === 'video') {
            ui.remoteVideo.style.opacity = enabled ? '1' : '0.2';
            ui.commStatus.textContent = enabled ? "SECURE SESSION LIVE" : "REMOTE CAMERA OFF";
        }
    }

    async function startCall(type) {
        if (!state.activeRecipient) return;
        state.activeCallType = type.includes('Video') ? 'Video' : 'Voice';

        ui.commName.textContent = state.activeRecipient;
        ui.commAvatar.textContent = state.activeRecipient[0].toUpperCase();
        ui.commStatus.textContent = `Dialing node...`;
        ui.commStatus.style.color = "var(--text-muted)";
        ui.commOverlay.classList.remove('hidden');
        ui.acceptCallBtn.classList.add('hidden');
        ui.callTimer.classList.add('hidden');

        // UI Handling for Voice vs Video
        if (state.activeCallType === 'Voice') {
            ui.localVideo.classList.add('hidden');
            ui.remoteVideo.classList.add('hidden');
            ui.commAvatar.classList.remove('hidden');
        } else {
            ui.commAvatar.classList.add('hidden');
        }

        state.isCommActive = true;

        // Send offer signal
        const signal = JSON.stringify({ type: "call_signal", subType: "offer", callType: state.activeCallType });
        fetch('/api/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-User-ID': state.currentUser },
            body: JSON.stringify({ recipient: state.activeRecipient, message: signal })
        });

        state.ringtone.play().catch(() => { });
        if (state.activeCallType === 'Video') initCamera();
    }

    function handleIncomingCall(caller, type) {
        state.activeRecipient = caller;
        state.activeCallType = type?.includes('Video') ? 'Video' : 'Voice';

        ui.commName.textContent = caller;
        ui.commAvatar.textContent = caller[0].toUpperCase();
        ui.commStatus.textContent = `INCOMING ${state.activeCallType.toUpperCase()}...`;
        ui.commStatus.style.color = "var(--primary)";
        ui.commOverlay.classList.remove('hidden');
        ui.acceptCallBtn.classList.remove('hidden');
        ui.callTimer.classList.add('hidden');

        if (state.activeCallType === 'Voice') {
            ui.localVideo.classList.add('hidden');
            ui.remoteVideo.classList.add('hidden');
            ui.commAvatar.classList.remove('hidden');
        }

        state.isCommActive = true;
        state.ringtone.play().catch(() => { });
    }

    async function establishLiveCall() {
        state.ringtone.pause();
        state.beepSound.play().catch(() => { });
        ui.commStatus.textContent = "SECURE SESSION LIVE";
        ui.commStatus.style.color = "var(--success)";
        ui.callTimer.classList.remove('hidden');
        startCallTimer();

        if (state.activeCallType === 'Video') {
            initCamera();
        } else {
            // Audio-only mode: ensure tracks are handled properly
            initAudioOnly();
        }
    }

    function remoteEndCall() {
        terminateSession();
    }

    function terminateSession() {
        // Log the call if it was live
        if (ui.commStatus.textContent === "SECURE SESSION LIVE" && state.activeRecipient) {
            const duration = ui.callTimer.textContent;
            const logContent = `${state.activeCallType} call ended`;
            const signal = JSON.stringify({ type: "call_signal", subType: "system_log", content: logContent, duration: duration });

            // Send log to history
            fetch('/api/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-User-ID': state.currentUser },
                body: JSON.stringify({ recipient: state.activeRecipient, message: signal })
            }).then(() => fetchMessages());
        }

        state.ringtone.pause();
        state.ringtone.currentTime = 0;
        ui.commOverlay.classList.add('hidden');
        ui.acceptCallBtn.classList.add('hidden');
        ui.commAvatar.classList.remove('hidden');
        ui.remoteVideo.classList.add('hidden');
        ui.localVideo.classList.add('hidden');
        ui.remoteVideo.srcObject = null;
        ui.commStatus.style.color = "var(--text-muted)";
        state.isCommActive = false;

        // Reset Toggles
        state.isMuted = false;
        state.isCamOff = false;
        ui.muteBtn.classList.remove('off');
        ui.toggleCamBtn.classList.remove('off');
        ui.muteBtn.innerHTML = '<i data-lucide="mic"></i>';
        ui.toggleCamBtn.innerHTML = '<i data-lucide="video"></i>';
        refreshIcons();

        stopCamera();
        stopCallTimer();
    }

    async function initCamera() {
        try {
            state.localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
            ui.localVideo.srcObject = state.localStream;
            ui.localVideo.classList.remove('hidden');

            // DUAL STREAM SIMULATION: For this demo on same machine,
            // we mirror the local stream to the remote view as well
            ui.remoteVideo.srcObject = state.localStream;
            ui.remoteVideo.classList.remove('hidden');
            ui.commAvatar.classList.add('hidden');
        } catch (e) {
            console.warn("Camera access denied or unavailable");
            ui.commAvatar.classList.remove('hidden');
        }
    }

    function stopCamera() {
        if (state.localStream) {
            state.localStream.getTracks().forEach(track => track.stop());
            state.localStream = null;
        }
        ui.localVideo.srcObject = null;
    }

    async function initAudioOnly() {
        try {
            state.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
            // Mirror local audio if needed, but usually just for P2P connection
        } catch (e) {
            console.warn("Microphone access denied");
        }
    }

    function startCallTimer() {
        stopCallTimer();
        state.callStartTime = Date.now();
        state.callTimerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - state.callStartTime) / 1000);
            const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
            const secs = (elapsed % 60).toString().padStart(2, '0');
            ui.callTimer.textContent = `${mins}:${secs}`;
        }, 1000);
    }

    function stopCallTimer() {
        if (state.callTimerInterval) clearInterval(state.callTimerInterval);
        ui.callTimer.textContent = "00:00";
    }

    // --- Utilities ---
    function startPolling() {
        fetchMessages();
        if (state.pollingInterval) clearInterval(state.pollingInterval);
        state.pollingInterval = setInterval(fetchMessages, 2000);
    }

    function debounce(func, timeout = 300) {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => { func.apply(this, args); }, timeout);
        };
    }

    function refreshIcons() {
        if (window.lucide) lucide.createIcons();
    }

    function formatBytes(bytes, decimals = 1) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
});
