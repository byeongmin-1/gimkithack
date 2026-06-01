// ==UserScript==
// @name         teddy
// @namespace    https://github.com/Zyrox-client
// @version      2.9.5
// @description  A modern userscript hacked client for gimkit
// @author       ZZZ
// @match        https://www.gimkit.com/join*
// @run-at       document-start
// @icon         https://raw.githubusercontent.com/Zyrox-client/Zyrox-gimkit-client/refs/heads/main/images/logo.png
// @license      MIT
// @grant        none
// @downloadURL https://update.greasyfork.org/scripts/572408/Zyrox%20client%20%28gimkit%29.user.js
// @updateURL https://update.greasyfork.org/scripts/572408/Zyrox%20client%20%28gimkit%29.meta.js
// ==/UserScript==

(() => {
    "use strict";

    // Some userscript runtimes execute bundled code that expects a global `Module`.
    // with `enable/disable` methods. Provide a minimal compatible fallback.
    if (typeof globalThis.Module === "undefined") {
        globalThis.Module = class Module {
            constructor(name = "Module", options = {}) {
                this.name = name;
                this.enabled = false;
                this.onEnable = typeof options.onEnable === "function" ? options.onEnable : () => { };
                this.onDisable = typeof options.onDisable === "function" ? options.onDisable : () => { };
            }

            enable() {
                if (this.enabled) return;
                this.enabled = true;
                this.onEnable();
            }

            disable() {
                if (!this.enabled) return;
                this.enabled = false;
                this.onDisable();
            }
        };
    }

    if (window.__TEDDY_UI_MOUNTED__) return;
    window.__TEDDY_UI_MOUNTED__ = true;

    function removeUnsupportedBrowserWarning() {
        const warningText = "Your browser does not fully support this page";
        const operaText = "Download Opera";
        const scan = () => {
            for (const el of document.querySelectorAll("div, section, aside, dialog, [role='dialog'], [role='alert']")) {
                const text = el.textContent || "";
                if (!text.includes(warningText) || !text.includes(operaText)) continue;
                el.remove();
            }
        };

        scan();
        const startObserver = () => {
            if (!document.body) return false;
            const observer = new MutationObserver(scan);
            observer.observe(document.body, { childList: true, subtree: true });
            scan();
            return true;
        };

        if (!startObserver()) {
            window.addEventListener("DOMContentLoaded", startObserver, { once: true });
        }
    }

    removeUnsupportedBrowserWarning();

    // ---------------------------------------------------------------------------
    // GIMKIT QUESTION FLOW (reverse-engineering notes)
    // ---------------------------------------------------------------------------
    // Short answer to: "is Gimkit choosing questions randomly on the client?"
    // -> Mostly no. The client *renders* and submits answers, but the server is the
    //    authority that sends/updates question payloads and validates outcomes.
    //
    // What we currently observe in packet captures (Classic / Draw That / Tycoon-like
    // modes) from this repo's test scripts and runtime hooks:
    // 1) Game traffic is a WebSocket on *.gimkitconnect.com, transported either as
    //    Blueboat-style msgpack events or Colyseus room messages.
    // 2) Question content appears in inbound server messages (ex: STATE_UPDATE /
    //    device state changes) as fields such as prompt/term/answers/correct index
    //    depending on mode implementation.
    // 3) The client sends player actions (selected answer, interaction, etc.) but
    //    does not become source-of-truth for score/currency/progression.
    // 4) "Random" ordering is usually server-side selection/shuffle from the active
    //    Kit/question pool; each client receives the next question state from server.
    //
    // Practical implication for modules:
    // - Auto-answer and "question reveal" logic should parse inbound socket state,
    //   not attempt local RNG prediction.
    // - Patching UI-only state can desync quickly because authoritative state is
    //   continuously pushed from server.
    //
    // Useful references inside this repo:
    // - tests/drawit-dump.js      (logs term-like answer candidates from STATE_UPDATE)
    // - tests/classic-autoanswer.js (classic answer extraction + submit path)
    // - tests/classic-logger.js     (general packet/event logging helpers)
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // AUTO-ANSWER PAGE-CONTEXT INJECTION
    // Injected as a real <script> tag so it runs in page scope and patches
    // window.WebSocket BEFORE Gimkit creates its connection.
    // Mirrors autoanswer.js 1:1, but exposes window.__TEDDYAutoAnswer.start/stop
    // so the TEDDY module toggle controls it.
    // ---------------------------------------------------------------------------
    (function injectAutoAnswerPageContext() {
        function pageMain() {
            const LOG = "[AutoAnswer][page]";
            const colyseusProtocol = { ROOM_DATA: 13 };

            function msgpackEncode(value) {
                const bytes = [];
                const deferred = [];
                const write = (input) => {
                    const type = typeof input;
                    if (type === "string") {
                        let len = 0;
                        for (let i = 0; i < input.length; i++) {
                            const code = input.charCodeAt(i);
                            if (code < 128) len++; else if (code < 2048) len += 2; else if (code < 55296 || code > 57343) len += 3; else { i++; len += 4; }
                        }
                        if (len < 32) bytes.push(160 | len); else if (len < 256) bytes.push(217, len); else bytes.push(218, len >> 8, len & 255);
                        deferred.push({ type: "string", value: input, offset: bytes.length });
                        bytes.length += len;
                        return;
                    }
                    if (type === "number") {
                        if (Number.isInteger(input) && input >= 0 && input < 128) { bytes.push(input); return; }
                        if (Number.isInteger(input) && input >= 0 && input < 65536) { bytes.push(205, input >> 8, input & 255); return; }
                        bytes.push(203); deferred.push({ type: "float64", value: input, offset: bytes.length }); bytes.length += 8; return;
                    }
                    if (type === "boolean") { bytes.push(input ? 195 : 194); return; }
                    if (input == null) { bytes.push(192); return; }
                    if (Array.isArray(input)) {
                        const len = input.length;
                        if (len < 16) bytes.push(144 | len); else bytes.push(220, len >> 8, len & 255);
                        for (const item of input) write(item);
                        return;
                    }
                    const keys = Object.keys(input);
                    const len = keys.length;
                    if (len < 16) bytes.push(128 | len); else bytes.push(222, len >> 8, len & 255);
                    for (const key of keys) { write(key); write(input[key]); }
                };
                write(value);
                const view = new DataView(new ArrayBuffer(bytes.length));
                for (let i = 0; i < bytes.length; i++) view.setUint8(i, bytes[i] & 255);
                for (const part of deferred) {
                    if (part.type === "float64") { view.setFloat64(part.offset, part.value); continue; }
                    let offset = part.offset;
                    const s = part.value;
                    for (let i = 0; i < s.length; i++) {
                        let code = s.charCodeAt(i);
                        if (code < 128) view.setUint8(offset++, code);
                        else if (code < 2048) { view.setUint8(offset++, 192 | (code >> 6)); view.setUint8(offset++, 128 | (code & 63)); }
                        else { view.setUint8(offset++, 224 | (code >> 12)); view.setUint8(offset++, 128 | ((code >> 6) & 63)); view.setUint8(offset++, 128 | (code & 63)); }
                    }
                }
                return view.buffer;
            }

            function msgpackDecode(buffer, startOffset = 0) {
                const view = new DataView(buffer);
                let offset = startOffset;
                const readString = (len) => {
                    let out = "";
                    const end = offset + len;
                    while (offset < end) {
                        const byte = view.getUint8(offset++);
                        if ((byte & 0x80) === 0) out += String.fromCharCode(byte);
                        else if ((byte & 0xe0) === 0xc0) out += String.fromCharCode(((byte & 0x1f) << 6) | (view.getUint8(offset++) & 0x3f));
                        else out += String.fromCharCode(((byte & 0x0f) << 12) | ((view.getUint8(offset++) & 0x3f) << 6) | (view.getUint8(offset++) & 0x3f));
                    }
                    return out;
                };
                const read = () => {
                    const token = view.getUint8(offset++);
                    if (token < 0x80) return token;
                    if (token < 0x90) { const size = token & 0x0f; const map = {}; for (let i = 0; i < size; i++) map[read()] = read(); return map; }
                    if (token < 0xa0) { const size = token & 0x0f; const arr = new Array(size); for (let i = 0; i < size; i++) arr[i] = read(); return arr; }
                    if (token < 0xc0) return readString(token & 0x1f);
                    if (token > 0xdf) return token - 256;
                    switch (token) {
                        case 192: return null;
                        case 194: return false;
                        case 195: return true;
                        case 202: { const n = view.getFloat32(offset); offset += 4; return n; }
                        case 203: { const n = view.getFloat64(offset); offset += 8; return n; }
                        case 204: { const n = view.getUint8(offset); offset += 1; return n; }
                        case 205: { const n = view.getUint16(offset); offset += 2; return n; }
                        case 206: { const n = view.getUint32(offset); offset += 4; return n; }
                        case 208: { const n = view.getInt8(offset); offset += 1; return n; }
                        case 209: { const n = view.getInt16(offset); offset += 2; return n; }
                        case 210: { const n = view.getInt32(offset); offset += 4; return n; }
                        case 217: { const n = view.getUint8(offset); offset += 1; return readString(n); }
                        case 218: { const n = view.getUint16(offset); offset += 2; return readString(n); }
                        case 220: { const size = view.getUint16(offset); offset += 2; const arr = new Array(size); for (let i = 0; i < size; i++) arr[i] = read(); return arr; }
                        case 222: { const size = view.getUint16(offset); offset += 2; const map = {}; for (let i = 0; i < size; i++) map[read()] = read(); return map; }
                        default: return null;
                    }
                };
                const value = read();
                return { value, offset };
            }

            function parseChangePacket(packet) {
                const out = [];
                for (const change of packet?.changes || []) {
                    const data = {};
                    const keys = change[1].map((index) => packet.values[index]);
                    for (let i = 0; i < keys.length; i++) data[keys[i]] = change[2][i];
                    out.push({ id: change[0], data });
                }
                return out;
            }

            class LocalSocketManager extends EventTarget {
                constructor() {
                    super();
                    this.socket = null;
                    this.transportType = "unknown";
                    this.blueboatRoomId = null;
                    this.playerId = null;
                    this.install();
                }
                install() {
                    const manager = this;
                    const NativeWebSocket = window.WebSocket;
                    window.WebSocket = class extends NativeWebSocket {
                        constructor(url, protocols) {
                            super(url, protocols);
                            if (String(url || "").includes("gimkitconnect.com")) manager.registerSocket(this);
                        }
                        send(data) {
                            manager.onSend(data);
                            super.send(data);
                        }
                    };
                }
                registerSocket(socket) {
                    this.socket = socket;
                    console.log(LOG, "Registered WebSocket", socket.url);
                    socket.addEventListener("message", (e) => {
                        const firstByte = (() => {
                            try {
                                return new Uint8Array(e.data)[0];
                            } catch (_) {
                                return null;
                            }
                        })();
                        if (this.transportType === "unknown" && firstByte != null) {
                            this.transportType = firstByte === 4 ? "blueboat" : "colyseus";
                        }
                        if (this.transportType === "blueboat") {
                            const decoded = this.decodeBlueboat(e.data);
                            if (!decoded) return;
                            this.dispatchEvent(new CustomEvent("blueboatMessage", { detail: decoded }));
                            if (typeof decoded.eventName === "string" && decoded.eventName.startsWith("message-")) {
                                this.blueboatRoomId = decoded.eventName.slice("message-".length);
                            }
                        } else {
                            const decoded = this.decodeColyseus(e.data);
                            if (!decoded) return;
                            this.dispatchEvent(new CustomEvent("colyseusMessage", { detail: decoded }));
                            if (decoded.type === "AUTH_ID") {
                                this.playerId = decoded.message;
                                console.log(LOG, "Got player id", this.playerId);
                            }
                            if (decoded.type === "DEVICES_STATES_CHANGES") {
                                const parsed = parseChangePacket(decoded.message);
                                this.dispatchEvent(new CustomEvent("deviceChanges", { detail: parsed }));
                            }
                        }
                    });
                }
                decodeBlueboat(data) {
                    const bytes = new Uint8Array(data);
                    if (!bytes.byteLength || bytes[0] !== 4) return null;
                    const decoded = msgpackDecode(data.slice(1), 0)?.value;
                    const payload = Array.isArray(decoded?.data) ? decoded.data[1] : decoded?.data;
                    return {
                        eventName: Array.isArray(decoded?.data) ? decoded.data[0] : null,
                        payload,
                    };
                }
                onSend(data) {
                    if (this.transportType !== "blueboat") return;
                    const decoded = this.decodeBlueboat(data);
                    if (!decoded) return;
                    if (decoded?.payload?.room) this.blueboatRoomId = decoded.payload.room;
                    if (decoded?.payload?.roomId) this.blueboatRoomId = decoded.payload.roomId;
                }
                decodeColyseus(data) {
                    const bytes = new Uint8Array(data);
                    if (bytes[0] !== colyseusProtocol.ROOM_DATA) return null;
                    const first = msgpackDecode(data, 1);
                    if (!first) return null;
                    let message;
                    if (bytes.byteLength > first.offset) {
                        const second = msgpackDecode(data, first.offset);
                        message = second?.value;
                    }
                    return { type: first.value, message };
                }
                sendMessage(channel, payload) {
                    if (!this.socket) return;
                    if (this.transportType === "blueboat") {
                        if (!this.blueboatRoomId) return;
                        const encoded = msgpackEncode({
                            type: 2,
                            data: ["blueboat_SEND_MESSAGE", { room: this.blueboatRoomId, key: channel, data: payload }],
                            options: { compress: true },
                            nsp: "/",
                        });
                        const out = new Uint8Array(1 + encoded.byteLength);
                        out[0] = 4;
                        out.set(new Uint8Array(encoded), 1);
                        this.socket.send(out.buffer);
                        return;
                    }
                    const header = new Uint8Array([colyseusProtocol.ROOM_DATA]);
                    const a = new Uint8Array(msgpackEncode(channel));
                    const b = new Uint8Array(msgpackEncode(payload));
                    const packet = new Uint8Array(header.length + a.length + b.length);
                    packet.set(header, 0);
                    packet.set(a, header.length);
                    packet.set(b, header.length + a.length);
                    this.socket.send(packet);
                }
            }

            const socketManager = window.socketManager || new LocalSocketManager();
            window.socketManager = socketManager;

            const state = {
                questions: [],
                questionById: new Map(),
                answerDeviceId: null,
                currentQuestionId: null,
                questionIdList: [],
                currentQuestionIndex: -1,
                sentQuestionIds: new Set(),
                isPardyMode: false,
                pardyCurrentQuestionId: null,
                pardyQuestionStatus: null,
                pardyAskQuestionId: null,
                pardyAskReadyAt: 0,
                pardyAskTimerId: null,
                lastPardyAnsweredQuestionId: null,
                lastPardySkipReason: null,
            };

            function setQuestions(questions) {
                state.questions = Array.isArray(questions) ? questions : [];
                const nextQuestionById = new Map();
                for (const question of state.questions) {
                    const id = question?._id || question?.id;
                    if (id) { nextQuestionById.set(id, question); nextQuestionById.set(String(id), question); }
                }
                state.questionById = nextQuestionById;
            }

            function asArray(value) {
                if (Array.isArray(value)) return value;
                return value == null ? [] : [value];
            }

            function parseQuestionAnswer(question) {
                if (!question) return null;
                const answers = Array.isArray(question.answers) ? question.answers : [];
                if (!answers.length) return null;
                if (question.type === "text") return answers[0]?.text || null;
                const correct = answers.find((a) => a?.correct) || answers[0];
                return correct?.id || correct?._id || correct?.text || null;
            }

            function findQuestionById(id) {
                if (id == null) return null;
                return state.questionById.get(id) || state.questionById.get(String(id)) || null;
            }

            function normalizeQuestionId(questionId) {
                if (questionId == null) return null;
                return String(questionId);
            }

            function setCurrentQuestionIndex(nextIndex) {
                if (!Number.isInteger(nextIndex)) return;
                if (state.currentQuestionIndex !== -1 && nextIndex < state.currentQuestionIndex) {
                    state.sentQuestionIds.clear();
                }
                state.currentQuestionIndex = nextIndex;
            }

            function resetAnsweredCache() {
                state.sentQuestionIds.clear();
                state.lastPardyAnsweredQuestionId = null;
                state.pardyAskQuestionId = null;
                state.pardyAskReadyAt = 0;
                if (state.pardyAskTimerId) { clearTimeout(state.pardyAskTimerId); state.pardyAskTimerId = null; }
            }

            function normalizeSpecialGameTypes(value) {
                return asArray(value).map((item) => String(item || "").toUpperCase());
            }

            function isPardySpecialGameType(value) {
                return normalizeSpecialGameTypes(value).includes("PARDY");
            }

            function logPardySkip(reason) {
                if (state.lastPardySkipReason === reason) return;
                state.lastPardySkipReason = reason;
                console.log(LOG, "PARDY auto-answer waiting:", reason);
            }

            function setPardyMode(enabled, source) {
                if (!enabled) return;
                if (!state.isPardyMode) {
                    state.isPardyMode = true;
                    console.log(LOG, "Detected PARDY game type from", source || "game state", "- using PARDY answer flow when Auto Answer is enabled");
                }
            }

            function readStateUpdateValue(updateValue, wantedKey) {
                for (const item of asArray(updateValue)) {
                    const value = item?.value;
                    if (value?.key === wantedKey) return value.value;
                    if (item?.key === wantedKey) return item.value;
                }
                return null;
            }

            function applyPardyQuestionId(questionId) {
                const normalizedQuestionId = normalizeQuestionId(questionId);
                if (!normalizedQuestionId) return;
                if (state.pardyCurrentQuestionId !== normalizedQuestionId) {
                    state.pardyCurrentQuestionId = normalizedQuestionId;
                    state.currentQuestionId = questionId;
                    state.pardyQuestionStatus = null;
                    state.pardyAskQuestionId = null;
                    state.pardyAskReadyAt = 0;
                    if (state.pardyAskTimerId) { clearTimeout(state.pardyAskTimerId); state.pardyAskTimerId = null; }
                    state.lastPardySkipReason = null;
                    console.log(LOG, "PARDY current question set", normalizedQuestionId);
                }
            }

            function applyPardyQuestionStatus(questionStatus) {
                if (questionStatus == null) return;
                const normalizedStatus = String(questionStatus).toLowerCase();
                state.pardyQuestionStatus = normalizedStatus;
                console.log(LOG, "PARDY question status", normalizedStatus);
                if (normalizedStatus !== "ask") return;
                const questionId = normalizeQuestionId(state.pardyCurrentQuestionId);
                if (!questionId) { logPardySkip("questionStatus ask received before currentQuestionId"); return; }
                state.pardyAskQuestionId = questionId;
                state.pardyAskReadyAt = Date.now() + Math.max(0, Number(_pardyDelay) || 0);
                state.lastPardySkipReason = null;
                if (state.pardyAskTimerId) clearTimeout(state.pardyAskTimerId);
                if (_running) {
                    state.pardyAskTimerId = setTimeout(() => {
                        state.pardyAskTimerId = null;
                        answerQuestion();
                    }, Math.max(0, state.pardyAskReadyAt - Date.now()));
                } else {
                    state.pardyAskTimerId = null;
                }
            }

            function getNextUnansweredQuestion() {
                const currentId = state.questionIdList[state.currentQuestionIndex];
                if (currentId) {
                    const current = findQuestionById(currentId);
                    const id = current?._id || current?.id;
                    if (current && id && !state.sentQuestionIds.has(normalizeQuestionId(id))) return current;
                }

                for (const questionId of state.questionIdList) {
                    if (!questionId || state.sentQuestionIds.has(normalizeQuestionId(questionId))) continue;
                    const match = findQuestionById(questionId);
                    if (match) return match;
                }

                return state.questions.find((q) => {
                    const id = q?._id || q?.id;
                    return id && !state.sentQuestionIds.has(normalizeQuestionId(id));
                }) || null;
            }

            function applyBlueboatStateUpdate(packet) {
                const key = packet?.key;
                const data = packet?.data;
                if (typeof key !== "string") return;

                if (key === "PLAYER_JOINS_STATIC_STATE") {
                    const gameOptions = data?.gameOptions || {};
                    if (isPardySpecialGameType(gameOptions.specialGameType)) setPardyMode(true, "PLAYER_JOINS_STATIC_STATE");
                }

                if (key === "STATE_UPDATE") {
                    const type = data?.type;
                    if (type === "GAME_QUESTIONS") {
                        setQuestions(data?.value);
                        console.log(LOG, "Got game questions", state.questions.length);
                    } else if (type === "PARDY_MODE_STATE") {
                        setPardyMode(true, "PARDY_MODE_STATE");
                        const questionId = readStateUpdateValue(data?.value, "currentQuestionId");
                        if (questionId != null) applyPardyQuestionId(questionId);
                        const questionStatus = readStateUpdateValue(data?.value, "questionStatus");
                        if (questionStatus != null) applyPardyQuestionStatus(questionStatus);
                    } else if (type === "PLAYER_QUESTION_LIST") {
                        state.questionIdList = data?.value?.questionList || [];
                        if (Number.isInteger(data?.value?.questionIndex)) setCurrentQuestionIndex(data.value.questionIndex);
                        resetAnsweredCache();
                    } else if (type === "PLAYER_QUESTION_LIST_INDEX") {
                        if (Number.isInteger(data?.value)) setCurrentQuestionIndex(data.value);
                    }
                } else if (key === "PLAYER_QUESTION_LIST" && data?.questionList) {
                    state.questionIdList = data.questionList;
                    if (Number.isInteger(data?.questionIndex)) setCurrentQuestionIndex(data.questionIndex);
                    resetAnsweredCache();
                } else if (key === "PLAYER_QUESTION_LIST_INDEX" && Number.isInteger(data)) {
                    setCurrentQuestionIndex(data);
                } else if (key === "GAME_QUESTIONS" && Array.isArray(data)) {
                    setQuestions(data);
                } else if (key === "QUESTION_REVEALED" && data) {
                    const question = data?.question || data;
                    const questionId = question?._id || question?.id;
                    if (questionId && !findQuestionById(questionId)) {
                        state.questions.push(question);
                        state.questionById.set(questionId, question);
                        state.questionById.set(String(questionId), question);
                    }
                }
            }

            function extractBlueboatStateCandidates(payload) {
                const candidates = [];
                for (const item of asArray(payload)) {
                    if (!item || typeof item !== "object") continue;
                    if (typeof item.key === "string") candidates.push(item);
                    if (item.data && typeof item.data === "object" && typeof item.data.key === "string") candidates.push(item.data);
                    if (Array.isArray(item.events)) {
                        for (const eventItem of item.events) {
                            if (eventItem && typeof eventItem === "object" && typeof eventItem.key === "string") candidates.push(eventItem);
                        }
                    }
                }
                return candidates;
            }

            function answerQuestion() {
                if (!_running) return;
                if (socketManager.transportType === "colyseus") {
                    if (state.currentQuestionId == null || state.answerDeviceId == null) return;
                    const question = findQuestionById(state.currentQuestionId);
                    if (!question) return;
                    const packet = { key: "answered", deviceId: state.answerDeviceId, data: {} };
                    packet.data.answer = parseQuestionAnswer(question);
                    if (!packet.data.answer) return;
                    socketManager.sendMessage("MESSAGE_FOR_DEVICE", packet);
                    console.log(LOG, "Answered colyseus", state.currentQuestionId);
                } else {
                    let question;
                    let rawQuestionId;
                    let questionId;

                    if (state.isPardyMode) {
                        questionId = normalizeQuestionId(state.pardyCurrentQuestionId);
                        if (!questionId) { logPardySkip("no PARDY currentQuestionId STATE_UPDATE yet"); return; }
                        if (state.pardyQuestionStatus !== "ask" || state.pardyAskQuestionId !== questionId) { logPardySkip("waiting for PARDY questionStatus ask"); return; }
                        if (Date.now() < state.pardyAskReadyAt) { logPardySkip("waiting for PARDY answer delay"); return; }
                        if (state.sentQuestionIds.has(questionId) || state.lastPardyAnsweredQuestionId === questionId) return;
                        question = findQuestionById(questionId);
                        if (!question) { logPardySkip(`question ${questionId} is not loaded yet`); return; }
                        rawQuestionId = question?._id || question?.id || state.pardyCurrentQuestionId;
                    } else {
                        question = getNextUnansweredQuestion();
                        if (!question) return;
                        rawQuestionId = question?._id || question?.id;
                        questionId = normalizeQuestionId(rawQuestionId);
                        if (!questionId || state.sentQuestionIds.has(normalizeQuestionId(questionId))) return;
                    }

                    const answer = parseQuestionAnswer(question);
                    if (!answer) {
                        if (state.isPardyMode) logPardySkip(`no answer found for question ${questionId}`);
                        return;
                    }
                    socketManager.sendMessage("QUESTION_ANSWERED", { questionId: rawQuestionId ?? questionId, answer });
                    state.sentQuestionIds.add(questionId);
                    if (state.isPardyMode) state.lastPardyAnsweredQuestionId = questionId;
                    state.lastPardySkipReason = null;
                    console.log(LOG, state.isPardyMode ? "Answered PARDY blueboat" : "Answered blueboat", questionId);
                }
            }

            socketManager.addEventListener("deviceChanges", (event) => {
                for (const { id, data } of event.detail || []) {
                    for (const key in data || {}) {
                        if (key === "GLOBAL_questions") {
                            try { setQuestions(JSON.parse(data[key])); } catch (_) { setQuestions(data[key]); }
                            state.answerDeviceId = id;
                            console.log(LOG, "Got questions", state.questions.length);
                        }
                        if (socketManager.playerId && key === `PLAYER_${socketManager.playerId}_currentQuestionId`) {
                            state.currentQuestionId = data[key];
                        }
                    }
                }
            });

            socketManager.addEventListener("blueboatMessage", (event) => {
                if (event.detail?.eventName === "blueboat_SEND_MESSAGE" && event.detail?.payload?.room) {
                    socketManager.blueboatRoomId = event.detail.payload.room;
                }
                const candidates = extractBlueboatStateCandidates(event.detail?.payload);
                for (const candidate of candidates) applyBlueboatStateUpdate(candidate);
            });

            // Expose start/stop so the TEDDY module toggle controls the interval
            let _timerId = null;
            let _running = false;
            let _baseSpeed = 1000;
            let _pardyDelay = 1500;
            const BLUEBOAT_EXTRA_DELAY_MS = 500;

            function getCurrentDelay() {
                if (socketManager.transportType === "blueboat") return _baseSpeed + BLUEBOAT_EXTRA_DELAY_MS;
                return _baseSpeed;
            }

            function scheduleNextTick() {
                if (!_running) return;
                const delay = Math.max(200, Number(getCurrentDelay()) || 1000);
                _timerId = setTimeout(() => {
                    answerQuestion();
                    scheduleNextTick();
                }, delay);
            }

            function startAutoAnswer(speed = 1000, source = "module toggle", options = {}) {
                const cfg = window.__TEDDYAutoAnswerConfig || {};
                _baseSpeed = Math.max(200, Number(speed ?? cfg.speed) || 1000);
                const pardyDelayNumber = Number(options?.pardyDelay ?? cfg.triviaDelay);
                _pardyDelay = Math.max(0, Math.min(8000, Number.isFinite(pardyDelayNumber) ? pardyDelayNumber : _pardyDelay));
                const wasRunning = _running;
                _running = true;
                if (_timerId) clearTimeout(_timerId);
                scheduleNextTick();
                console.log(LOG, wasRunning ? "Auto-answer timer refreshed by" : "Auto-answer started by", source);
            }

            window.__zyroxAutoAnswer = {
                start(speed = 1000, options = {}) {
                    startAutoAnswer(speed, "module toggle", options);
                },
                stop() {
                    _running = false;
                    if (_timerId) { clearTimeout(_timerId); _timerId = null; }
                    if (state.pardyAskTimerId) { clearTimeout(state.pardyAskTimerId); state.pardyAskTimerId = null; }
                },
            };
            console.log(LOG, "Page context ready, waiting for module toggle.");
        }

        const el = document.createElement("script");
        el.textContent = `;(${pageMain.toString()})();`;
        (document.head || document.documentElement).appendChild(el);
        el.remove();
    })();

    (function injectEspPageContextBridge() {
        function pageMain() {
            const LOG = "[ESP][page]";
            const shared = {
                ready: false,
                lastUpdate: 0,
                localPlayerId: null,
                localTeamId: null,
                camera: null,
                players: [],
            };
            const UPDATE_INTERVAL_MS = 50;
            let lastProcessedAt = 0;
            window.__zyroxEspShared = shared;

            function tick() {
                const now = performance.now();
                if (now - lastProcessedAt < UPDATE_INTERVAL_MS) {
                    requestAnimationFrame(tick);
                    return;
                }
                lastProcessedAt = now;
                const serializer = window?.serializer;
                const characters = serializer?.state?.characters?.$items;
                const camera = window?.stores?.phaser?.scene?.cameras?.cameras?.[0];
                const localPlayerId = window?.socketManager?.playerId ?? null;
                const localCharacter = localPlayerId != null ? characters?.get?.(localPlayerId) : null;
                const localTeamId = localCharacter?.teamId ?? null;

                if (!characters || typeof characters[Symbol.iterator] !== "function" || !camera || localPlayerId == null || localTeamId == null) {
                    shared.ready = false;
                    shared.lastUpdate = Date.now();
                    requestAnimationFrame(tick);
                    return;
                }

                const outPlayers = [];
                for (const [id, character] of characters) {
                    const x = Number(character?.x);
                    const y = Number(character?.y);
                    if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
                    outPlayers.push({
                        id: String(id ?? character?.id ?? "unknown"),
                        name: String(character?.name ?? character?.displayName ?? character?.username ?? id ?? "Unknown"),
                        teamId: character?.teamId ?? null,
                        x,
                        y,
                    });
                }

                shared.ready = true;
                shared.lastUpdate = Date.now();
                shared.localPlayerId = localPlayerId;
                shared.localTeamId = localTeamId;
                shared.camera = {
                    midX: Number(camera?.midPoint?.x ?? 0),
                    midY: Number(camera?.midPoint?.y ?? 0),
                    zoom: Number(camera?.zoom ?? 1),
                };
                shared.players = outPlayers;
                requestAnimationFrame(tick);
            }

            requestAnimationFrame(tick);
            console.log(LOG, "Bridge ready");
        }

        const el = document.createElement("script");
        el.textContent = `;(${pageMain.toString()})();`;
        (document.head || document.documentElement).appendChild(el);
        el.remove();
    })();

    function readUserscriptVersion() {

        const CLIENT_VERSION = "2.9.5";
        return CLIENT_VERSION;
    }

    const CONFIG = {
        toggleKey: "\\",
        defaultToggleKey: "\\",
        title: "Teddy",
        subtitle: "Client",
        version: readUserscriptVersion(),
        logoUrl: "https://raw.githubusercontent.com/Zyrox-client/Zyrox-gimkit-client/refs/heads/main/images/logo.png",
    };

    // --- Core Utilities & Networking (Extracted from Gimkit Cheat) ---

    const colyseusProtocol = {
        HANDSHAKE: 9,
        JOIN_ROOM: 10,
        ERROR: 11,
        LEAVE_ROOM: 12,
        ROOM_DATA: 13,
        ROOM_STATE: 14,
        ROOM_STATE_PATCH: 15,
        ROOM_DATA_SCHEMA: 16,
        ROOM_DATA_BYTES: 17,
    };
    const colyseusProtocolCodeSet = new Set(Object.values(colyseusProtocol));

    function utf8Read(view, offset) {
        const length = view[offset++];
        let string = "";
        for (let i = offset, end = offset + length; i < end; i++) {
            const byte = view[i];
            if ((byte & 0x80) === 0x00) {
                string += String.fromCharCode(byte);
            } else if ((byte & 0xe0) === 0xc0) {
                string += String.fromCharCode(((byte & 0x1f) << 6) | (view[++i] & 0x3f));
            } else if ((byte & 0xf0) === 0xe0) {
                string += String.fromCharCode(((byte & 0x0f) << 12) | ((view[++i] & 0x3f) << 6) | ((view[++i] & 0x3f) << 0));
            }
        }
        return string;
    }

    function parseChangePacket(packet) {
        const out = [];
        for (const change of packet?.changes || []) {
            const data = {};
            const keys = change[1].map((index) => packet.values[index]);
            for (let i = 0; i < keys.length; i++) data[keys[i]] = change[2][i];
            out.push({ id: change[0], data });
        }
        return out;
    }

    function msgpackEncode(value) {
        const bytes = [];
        const deferred = [];
        const write = (input) => {
            const type = typeof input;
            if (type === "string") {
                let len = 0;
                for (let i = 0; i < input.length; i++) {
                    const code = input.charCodeAt(i);
                    if (code < 128) len++;
                    else if (code < 2048) len += 2;
                    else if (code < 55296 || code > 57343) len += 3;
                    else {
                        i++;
                        len += 4;
                    }
                }
                if (len < 32) bytes.push(160 | len);
                else if (len < 256) bytes.push(217, len);
                else if (len < 65536) bytes.push(218, len >> 8, len & 255);
                else bytes.push(219, len >> 24, (len >> 16) & 255, (len >> 8) & 255, len & 255);
                deferred.push({ type: "string", value: input, offset: bytes.length });
                bytes.length += len;
                return;
            }
            if (type === "number") {
                if (Number.isInteger(input) && Number.isFinite(input)) {
                    if (input >= 0) {
                        if (input < 128) bytes.push(input);
                        else if (input < 256) bytes.push(204, input);
                        else if (input < 65536) bytes.push(205, input >> 8, input & 255);
                        else if (input < 4294967296) bytes.push(206, input >> 24, (input >> 16) & 255, (input >> 8) & 255, input & 255);
                        else {
                            const hi = Math.floor(input / Math.pow(2, 32));
                            const lo = input >>> 0;
                            bytes.push(207, hi >> 24, (hi >> 16) & 255, (hi >> 8) & 255, hi & 255, lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255, lo & 255);
                        }
                    } else if (input >= -32) bytes.push(input);
                    else if (input >= -128) bytes.push(208, input & 255);
                    else if (input >= -32768) bytes.push(209, (input >> 8) & 255, input & 255);
                    else if (input >= -2147483648) bytes.push(210, (input >> 24) & 255, (input >> 16) & 255, (input >> 8) & 255, input & 255);
                    else {
                        const hi = Math.floor(input / Math.pow(2, 32));
                        const lo = input >>> 0;
                        bytes.push(211, hi >> 24, (hi >> 16) & 255, (hi >> 8) & 255, hi & 255, lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255, lo & 255);
                    }
                    return;
                }
                bytes.push(203);
                deferred.push({ type: "float64", value: input, offset: bytes.length });
                bytes.length += 8;
                return;
            }
            if (type === "boolean") {
                bytes.push(input ? 195 : 194);
                return;
            }
            if (input == null) {
                bytes.push(192);
                return;
            }
            if (Array.isArray(input)) {
                const len = input.length;
                if (len < 16) bytes.push(144 | len);
                else if (len < 65536) bytes.push(220, len >> 8, len & 255);
                else bytes.push(221, len >> 24, (len >> 16) & 255, (len >> 8) & 255, len & 255);
                for (const item of input) write(item);
                return;
            }
            const keys = Object.keys(input).filter((k) => typeof input[k] !== "function");
            const len = keys.length;
            if (len < 16) bytes.push(128 | len);
            else if (len < 65536) bytes.push(222, len >> 8, len & 255);
            else bytes.push(223, len >> 24, (len >> 16) & 255, (len >> 8) & 255, len & 255);
            for (const key of keys) {
                write(key);
                write(input[key]);
            }
        };

        write(value);
        const view = new DataView(new ArrayBuffer(bytes.length));
        for (let i = 0; i < bytes.length; i++) view.setUint8(i, bytes[i] & 255);

        for (const part of deferred) {
            if (part.type === "float64") {
                view.setFloat64(part.offset, part.value);
                continue;
            }
            let offset = part.offset;
            const value = part.value;
            for (let i = 0; i < value.length; i++) {
                let code = value.charCodeAt(i);
                if (code < 128) view.setUint8(offset++, code);
                else if (code < 2048) {
                    view.setUint8(offset++, 192 | (code >> 6));
                    view.setUint8(offset++, 128 | (code & 63));
                } else if (code < 55296 || code > 57343) {
                    view.setUint8(offset++, 224 | (code >> 12));
                    view.setUint8(offset++, 128 | ((code >> 6) & 63));
                    view.setUint8(offset++, 128 | (code & 63));
                } else {
                    i++;
                    code = 65536 + (((code & 1023) << 10) | (value.charCodeAt(i) & 1023));
                    view.setUint8(offset++, 240 | (code >> 18));
                    view.setUint8(offset++, 128 | ((code >> 12) & 63));
                    view.setUint8(offset++, 128 | ((code >> 6) & 63));
                    view.setUint8(offset++, 128 | (code & 63));
                }
            }
        }
        return view.buffer;
    }

    function msgpackDecode(buffer, startOffset = 0) {
        const view = new DataView(buffer);
        let offset = startOffset;

        const readString = (len) => {
            let out = "";
            const end = offset + len;
            while (offset < end) {
                const byte = view.getUint8(offset++);
                if ((byte & 0x80) === 0) out += String.fromCharCode(byte);
                else if ((byte & 0xe0) === 0xc0) out += String.fromCharCode(((byte & 0x1f) << 6) | (view.getUint8(offset++) & 0x3f));
                else if ((byte & 0xf0) === 0xe0) out += String.fromCharCode(((byte & 0x0f) << 12) | ((view.getUint8(offset++) & 0x3f) << 6) | (view.getUint8(offset++) & 0x3f));
                else {
                    const codePoint = ((byte & 0x07) << 18) | ((view.getUint8(offset++) & 0x3f) << 12) | ((view.getUint8(offset++) & 0x3f) << 6) | (view.getUint8(offset++) & 0x3f);
                    const cp = codePoint - 0x10000;
                    out += String.fromCharCode((cp >> 10) + 0xd800, (cp & 1023) + 0xdc00);
                }
            }
            return out;
        };

        const read = () => {
            const token = view.getUint8(offset++);
            if (token < 0x80) return token;
            if (token < 0x90) {
                const size = token & 0x0f;
                const map = {};
                for (let i = 0; i < size; i++) map[read()] = read();
                return map;
            }
            if (token < 0xa0) {
                const size = token & 0x0f;
                const arr = new Array(size);
                for (let i = 0; i < size; i++) arr[i] = read();
                return arr;
            }
            if (token < 0xc0) return readString(token & 0x1f);
            if (token > 0xdf) return token - 256;
            switch (token) {
                case 192: return null;
                case 194: return false;
                case 195: return true;
                case 196: { const n = view.getUint8(offset); offset += 1; const b = buffer.slice(offset, offset + n); offset += n; return b; }
                case 197: { const n = view.getUint16(offset); offset += 2; const b = buffer.slice(offset, offset + n); offset += n; return b; }
                case 198: { const n = view.getUint32(offset); offset += 4; const b = buffer.slice(offset, offset + n); offset += n; return b; }
                case 202: { const v = view.getFloat32(offset); offset += 4; return v; }
                case 203: { const v = view.getFloat64(offset); offset += 8; return v; }
                case 204: { const v = view.getUint8(offset); offset += 1; return v; }
                case 205: { const v = view.getUint16(offset); offset += 2; return v; }
                case 206: { const v = view.getUint32(offset); offset += 4; return v; }
                case 207: { const hi = view.getUint32(offset); const lo = view.getUint32(offset + 4); offset += 8; return (hi * Math.pow(2, 32)) + lo; }
                case 208: { const v = view.getInt8(offset); offset += 1; return v; }
                case 209: { const v = view.getInt16(offset); offset += 2; return v; }
                case 210: { const v = view.getInt32(offset); offset += 4; return v; }
                case 211: { const hi = view.getInt32(offset); const lo = view.getUint32(offset + 4); offset += 8; return (hi * Math.pow(2, 32)) + lo; }
                case 217: { const n = view.getUint8(offset); offset += 1; return readString(n); }
                case 218: { const n = view.getUint16(offset); offset += 2; return readString(n); }
                case 219: { const n = view.getUint32(offset); offset += 4; return readString(n); }
                case 220: { const n = view.getUint16(offset); offset += 2; const arr = []; for (let i = 0; i < n; i++) arr.push(read()); return arr; }
                case 221: { const n = view.getUint32(offset); offset += 4; const arr = []; for (let i = 0; i < n; i++) arr.push(read()); return arr; }
                case 222: { const n = view.getUint16(offset); offset += 2; const map = {}; for (let i = 0; i < n; i++) map[read()] = read(); return map; }
                case 223: { const n = view.getUint32(offset); offset += 4; const map = {}; for (let i = 0; i < n; i++) map[read()] = read(); return map; }
                default: return null;
            }
        };

        return { value: read(), offset };
    }

    // Simplified msgpack-like encoding/decoding for Blueboat
    const blueboat = (() => {
        function encode(t, e, s) {
            let o = Array.isArray(t) ? { type: 2, data: t, options: { compress: !0 }, nsp: "/" } : { type: 2, data: ["blueboat_SEND_MESSAGE", { room: s, key: t, data: e }], options: { compress: !0 }, nsp: "/" };
            return (function (t) {
                let e = [], i = [], s = function t(e, n, i) {
                    let s = typeof i, o = 0, r = 0, a = 0, c = 0, l = 0, u = 0;
                    if ("string" === s) {
                        l = (function (t) {
                            let e = 0, n = 0, i = 0, s = t.length;
                            for (i = 0; i < s; i++) (e = t.charCodeAt(i)) < 128 ? n += 1 : e < 2048 ? n += 2 : e < 55296 || 57344 <= e ? n += 3 : (i++, n += 4);
                            return n;
                        })(i);
                        if (l < 32) e.push(160 | l), u = 1;
                        else if (l < 256) e.push(217, l), u = 2;
                        else if (l < 65536) e.push(218, l >> 8, l), u = 3;
                        else e.push(219, l >> 24, l >> 16, l >> 8, l), u = 5;
                        return n.push({ h: i, u: l, t: e.length }), u + l;
                    }
                    if ("number" === s) {
                        if (Math.floor(i) === i && isFinite(i)) {
                            if (i >= 0) {
                                if (i < 128) return e.push(i), 1;
                                if (i < 256) return e.push(204, i), 2;
                                if (i < 65536) return e.push(205, i >> 8, i), 3;
                                if (i < 4294967296) return e.push(206, i >> 24, i >> 16, i >> 8, i), 5;
                                a = i / Math.pow(2, 32) >> 0; c = i >>> 0; e.push(207, a >> 24, a >> 16, a >> 8, a, c >> 24, c >> 16, c >> 8, c); return 9;
                            } else {
                                if (i >= -32) return e.push(i), 1;
                                if (i >= -128) return e.push(208, i), 2;
                                if (i >= -32768) return e.push(209, i >> 8, i), 3;
                                if (i >= -2147483648) return e.push(210, i >> 24, i >> 16, i >> 8, i), 5;
                                a = Math.floor(i / Math.pow(2, 32)); c = i >>> 0; e.push(211, a >> 24, a >> 16, a >> 8, a, c >> 24, c >> 16, c >> 8, c); return 9;
                            }
                        } else {
                            e.push(203); n.push({ o: i, u: 8, t: e.length }); return 9;
                        }
                    }
                    if ("object" === s) {
                        if (null === i) return e.push(192), 1;
                        if (Array.isArray(i)) {
                            l = i.length;
                            if (l < 16) e.push(144 | l), u = 1;
                            else if (l < 65536) e.push(220, l >> 8, l), u = 3;
                            else e.push(221, l >> 24, l >> 16, l >> 8, l), u = 5;
                            for (o = 0; o < l; o++) u += t(e, n, i[o]);
                            return u;
                        }
                        let d = [], f = "", p = Object.keys(i);
                        for (o = 0, r = p.length; o < r; o++) "function" != typeof i[f = p[o]] && d.push(f);
                        l = d.length;
                        if (l < 16) e.push(128 | l), u = 1;
                        else if (l < 65536) e.push(222, l >> 8, l), u = 3;
                        else e.push(223, l >> 24, l >> 16, l >> 8, l), u = 5;
                        for (o = 0; o < l; o++) u += t(e, n, f = d[o]), u += t(e, n, i[f]);
                        return u;
                    }
                    if ("boolean" === s) return e.push(i ? 195 : 194), 1;
                    return 0;
                }(e, i, t);
                let o = new ArrayBuffer(s), r = new DataView(o), a = 0, c = 0, l = -1;
                if (i.length > 0) l = i[0].t;
                for (let u, h = 0, d = 0, f = 0, p = e.length; f < p; f++) {
                    r.setUint8(c + f, e[f]);
                    if (f + 1 === l) {
                        u = i[a]; h = u.u; d = c + l;
                        if (u.l) { let g = new Uint8Array(u.l); for (let E = 0; E < h; E++) r.setUint8(d + E, g[E]); }
                        else if (u.h) { (function (t, e, n) { for (let i = 0, s = 0, o = n.length; s < o; s++) (i = n.charCodeAt(s)) < 128 ? t.setUint8(e++, i) : (i < 2048 ? t.setUint8(e++, 192 | i >> 6) : (i < 55296 || 57344 <= i ? t.setUint8(e++, 224 | i >> 12) : (s++, i = 65536 + ((1023 & i) << 10 | 1023 & n.charCodeAt(s)), t.setUint8(e++, 240 | i >> 18), t.setUint8(e++, 128 | i >> 12 & 63)), t.setUint8(e++, 128 | i >> 6 & 63)), t.setUint8(e++, 128 | 63 & i)); })(r, d, u.h); }
                        else if (void 0 !== u.o) r.setFloat64(d, u.o);
                        c += h; if (i[++a]) l = i[a].t;
                    }
                }
                let y = Array.from(new Uint8Array(o)); y.unshift(4); return new Uint8Array(y).buffer;
            })(o);
        }

        function decode(packet) {
            function e(t) {
                this.t = 0;
                if (t instanceof ArrayBuffer) { this.i = t; this.s = new DataView(this.i); }
                else { if (!ArrayBuffer.isView(t)) return null; this.i = t.buffer; this.s = new DataView(this.i, t.byteOffset, t.byteLength); }
            }
            e.prototype.g = function (t) { let e = new Array(t); for (let n = 0; n < t; n++) e[n] = this.v(); return e; };
            e.prototype.M = function (t) { let e = {}; for (let n = 0; n < t; n++) e[this.v()] = this.v(); return e; };
            e.prototype.h = function (t) {
                let e = (function (t, e, n) {
                    let i = "", s = 0, o = e, r = e + n;
                    for (; o < r; o++) {
                        let a = t.getUint8(o);
                        if (0 != (128 & a)) {
                            if (192 != (224 & a)) {
                                if (224 != (240 & a)) {
                                    s = (7 & a) << 18 | (63 & t.getUint8(++o)) << 12 | (63 & t.getUint8(++o)) << 6 | (63 & t.getUint8(++o)) << 0;
                                    if (65536 <= s) { s -= 65536; i += String.fromCharCode(55296 + (s >>> 10), 56320 + (1023 & s)); }
                                    else i += String.fromCharCode(s);
                                } else i += String.fromCharCode((15 & a) << 12 | (63 & t.getUint8(++o)) << 6 | (63 & t.getUint8(++o)) << 0);
                            } else i += String.fromCharCode((31 & a) << 6 | 63 & t.getUint8(++o));
                        } else i += String.fromCharCode(a);
                    }
                    return i;
                })(this.s, this.t, t);
                this.t += t; return e;
            };
            e.prototype.l = function (t) { let e = this.i.slice(this.t, this.t + t); this.t += t; return e; };
            e.prototype.v = function () {
                if (!this.s) return null;
                let t, e = this.s.getUint8(this.t++), n = 0, i = 0, s = 0, o = 0;
                if (e < 192) return e < 128 ? e : e < 144 ? this.M(15 & e) : e < 160 ? this.g(15 & e) : this.h(31 & e);
                if (223 < e) return -1 * (255 - e + 1);
                switch (e) {
                    case 192: return null;
                    case 194: return !1;
                    case 195: return !0;
                    case 196: n = this.s.getUint8(this.t); this.t += 1; return this.l(n);
                    case 197: n = this.s.getUint16(this.t); this.t += 2; return this.l(n);
                    case 198: n = this.s.getUint32(this.t); this.t += 4; return this.l(n);
                    case 202: t = this.s.getFloat32(this.t); this.t += 4; return t;
                    case 203: t = this.s.getFloat64(this.t); this.t += 8; return t;
                    case 204: t = this.s.getUint8(this.t); this.t += 1; return t;
                    case 205: t = this.s.getUint16(this.t); this.t += 2; return t;
                    case 206: t = this.s.getUint32(this.t); this.t += 4; return t;
                    case 207: s = this.s.getUint32(this.t) * Math.pow(2, 32); o = this.s.getUint32(this.t + 4); this.t += 8; return s + o;
                    case 208: t = this.s.getInt8(this.t); this.t += 1; return t;
                    case 209: t = this.s.getInt16(this.t); this.t += 2; return t;
                    case 210: t = this.s.getInt32(this.t); this.t += 4; return t;
                    case 211: s = this.s.getInt32(this.t) * Math.pow(2, 32); o = this.s.getUint32(this.t + 4); this.t += 8; return s + o;
                    case 217: n = this.s.getUint8(this.t); this.t += 1; return this.h(n);
                    case 218: n = this.s.getUint16(this.t); this.t += 2; return this.h(n);
                    case 219: n = this.s.getUint32(this.t); this.t += 4; return this.h(n);
                    case 220: n = this.s.getUint16(this.t); this.t += 2; return this.g(n);
                    case 221: n = this.s.getUint32(this.t); this.t += 4; return this.g(n);
                    case 222: n = this.s.getUint16(this.t); this.t += 2; return this.M(n);
                    case 223: n = this.s.getUint32(this.t); this.t += 4; return this.M(n);
                }
                return null;
            };
            let q = (function (t) { let n = new e(t = t.slice(1)), i = n.v(); if (n.t === t.byteLength) return i; return null; })(packet);
            return q?.data?.[1];
        }
        return { encode, decode };
    })();

    function decodeBlueboatBinaryPacket(packet) {
        if (!(packet instanceof ArrayBuffer)) return null;
        const bytes = new Uint8Array(packet);
        if (!bytes.byteLength || bytes[0] !== 4) return null;
        const decoded = msgpackDecode(packet.slice(1), 0)?.value;
        if (!decoded || typeof decoded !== "object") return null;
        const data = decoded?.data;
        const eventName = Array.isArray(data) ? data[0] : null;
        const payload = Array.isArray(data) ? data[1] : data;
        return { eventName, payload, raw: decoded };
    }

    class SocketManager extends EventTarget {
        constructor() {
            super();
            this.socket = null;
            this.transportType = "unknown";
            this.blueboatRoomId = null;
            this.playerId = null;
            this.setup();
        }
        setup() {
            const manager = this;
            const shouldTrackSocketUrl = (url) => String(url || "").includes("gimkitconnect.com");
            class NewWebSocket extends WebSocket {
                constructor(url, params) {
                    super(url, params);
                    if (shouldTrackSocketUrl(url)) manager.registerSocket(this);
                }
                send(data) {
                    manager.onSend(data);
                    super.send(data);
                }
            }
            const nativeXMLSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.send = function () {
                this.addEventListener("load", () => {
                    if (!this.responseURL.endsWith("/matchmaker/join")) return;
                    try {
                        const response = JSON.parse(this.responseText);
                        manager.blueboatRoomId = response.roomId;
                    } catch (_) { }
                });
                nativeXMLSend.apply(this, arguments);
            };
            window.WebSocket = NewWebSocket;
            globalThis.socketManager = this;
        }
        registerSocket(socket) {
            this.socket = socket;
            const socketUrl = String(socket?.url || "");
            const looksLikeColyseus = socketUrl.includes("gimkitconnect.com") && !socketUrl.includes("/socket.io/");
            this.transportType = looksLikeColyseus ? "colyseus" : "unknown";
            this.addEventListener("colyseusMessage", (e) => {
                if (e.detail.type !== "DEVICES_STATES_CHANGES") return;
                this.dispatchEvent(new CustomEvent("deviceChanges", { detail: parseChangePacket(e.detail.message) }));
            });
            socket.addEventListener("message", (e) => {
                const blueboatDecoded = decodeBlueboatBinaryPacket(e.data) || blueboat.decode(e.data) || null;
                if (blueboatDecoded) {
                    const normalizedBlueboat = blueboatDecoded?.payload && typeof blueboatDecoded.payload === "object"
                        ? { ...blueboatDecoded.payload, eventName: blueboatDecoded.eventName, payload: blueboatDecoded.payload, raw: blueboatDecoded.raw }
                        : blueboatDecoded;
                    this.dispatchEvent(new CustomEvent("blueboatMessage", { detail: normalizedBlueboat }));
                }
                const firstByte = (() => {
                    try {
                        return new Uint8Array(e.data)[0];
                    } catch (_) {
                        return null;
                    }
                })();
                if (this.transportType === "unknown" && firstByte != null) {
                    if (colyseusProtocolCodeSet.has(firstByte)) this.transportType = "colyseus";
                    else this.transportType = "blueboat";
                }

                let decoded;
                if (this.transportType === "colyseus") {
                    decoded = this.decodeColyseus(e);
                    if (decoded) {
                        this.dispatchEvent(new CustomEvent("colyseusMessage", { detail: decoded }));
                        if (decoded.type === "AUTH_ID") {
                            this.playerId = decoded.message;
                        }
                    }
                } else {
                    // already emitted above via universal Blueboat decode path
                }
            });
        }
        onSend(data) {
            const safeDecodeBlueboat = (packet) => {
                if (!(packet instanceof ArrayBuffer) && !ArrayBuffer.isView(packet)) return null;
                const bytes = packet instanceof ArrayBuffer ? new Uint8Array(packet) : new Uint8Array(packet.buffer, packet.byteOffset, packet.byteLength);
                if (!bytes.length || bytes[0] !== 4) return null;
                try {
                    return blueboat.decode(packet);
                } catch (_) {
                    return null;
                }
            };
            if (this.transportType === "blueboat" && !this.blueboatRoomId) {
                const decoded = safeDecodeBlueboat(data);
                if (decoded?.roomId) this.blueboatRoomId = decoded.roomId;
                if (decoded?.room) this.blueboatRoomId = decoded.room;
            }
            const outbound = safeDecodeBlueboat(data);
            if (outbound) {
                this.dispatchEvent(new CustomEvent("blueboatSend", { detail: outbound }));
            }
        }
        sendMessage(channel, data) {
            if (!this.socket) return;
            const shouldUseColyseus = this.transportType === "colyseus" && !this.blueboatRoomId;
            if (!this.blueboatRoomId && !shouldUseColyseus) return;
            let encoded;
            if (shouldUseColyseus) {
                const header = new Uint8Array([colyseusProtocol.ROOM_DATA]);
                const channelEncoded = msgpackEncode(channel);
                const packetEncoded = msgpackEncode(data);
                encoded = new Uint8Array(header.length + channelEncoded.byteLength + packetEncoded.byteLength);
                encoded.set(header, 0);
                encoded.set(new Uint8Array(channelEncoded), header.length);
                encoded.set(new Uint8Array(packetEncoded), header.length + channelEncoded.byteLength);
                this.socket.send(encoded);
            } else {
                encoded = blueboat.encode(channel, data, this.blueboatRoomId);
                this.socket.send(encoded);
            }
        }
        decodeColyseus(event) {
            const bytes = new Uint8Array(event.data);
            const code = bytes[0];
            if (code === colyseusProtocol.ROOM_DATA) {
                const first = msgpackDecode(event.data, 1);
                if (!first) return null;
                let message;
                if (bytes.byteLength > first.offset) {
                    const second = msgpackDecode(event.data, first.offset);
                    message = second?.value;
                }
                return { type: first.value, message };
            }
            return null;
        }
    }

    const socketManager = new SocketManager();

    const TRUST_NO_ONE_MODULE_NAME = "Trust No One";
    const trustNoOneState = {
        enabled: false,
        listenerInstalled: false,
        panel: null,
        status: null,
        latestPeople: null,
    };

    function ensureTrustNoOnePanel() {
        if (trustNoOneState.panel?.isConnected) return;

        if (!document.getElementById("zyrox-trust-no-one-style")) {
            const style = document.createElement("style");
            style.id = "zyrox-trust-no-one-style";
            style.textContent = `
        #zyrox-trust-no-one-helper {
          position: fixed;
          top: 14px;
          right: 14px;
          z-index: 2147483647;
          min-width: 220px;
          max-width: 320px;
          padding: 10px 12px;
          border: 1px solid rgba(255, 75, 75, .72);
          border-radius: 8px;
          background: rgba(12, 10, 12, .92);
          color: #fff;
          font-family: Arial, sans-serif;
          box-shadow: 0 8px 26px rgba(0, 0, 0, .35);
        }
        #zyrox-trust-no-one-title {
          font-size: 12px;
          font-weight: 800;
          margin-bottom: 6px;
          color: #ff6868;
        }
        #zyrox-trust-no-one-status {
          font-size: 12px;
          line-height: 1.35;
          overflow-wrap: anywhere;
        }
      `;
            (document.head || document.documentElement).appendChild(style);
        }

        const panel = document.createElement("div");
        panel.id = "zyrox-trust-no-one-helper";

        const title = document.createElement("div");
        title.id = "zyrox-trust-no-one-title";
        title.textContent = "Trust No One";

        const status = document.createElement("div");
        status.id = "zyrox-trust-no-one-status";
        status.textContent = "Imposters: Waiting...";

        panel.append(title, status);
        (document.body || document.documentElement).appendChild(panel);

        trustNoOneState.panel = panel;
        trustNoOneState.status = status;
    }

    function renderTrustNoOneImposters() {
        if (!trustNoOneState.enabled) return;
        ensureTrustNoOnePanel();
        const people = Array.isArray(trustNoOneState.latestPeople) ? trustNoOneState.latestPeople : [];
        const imposters = people.filter((person) => person?.role === "imposter");
        const names = imposters.map((person) => String(person?.name || "Unknown"));
        trustNoOneState.status.textContent = names.length
            ? `Imposter(s): ${names.join(", ")}`
            : "Imposters: Waiting...";
    }

    function getTrustNoOnePeopleFromPacket(packet) {
        const key = packet?.key ?? packet?.payload?.key ?? packet?.data?.key;
        if (key !== "IMPOSTER_MODE_PEOPLE") return null;
        return packet?.data ?? packet?.payload?.data ?? null;
    }

    function handleTrustNoOnePacket(event) {
        const people = getTrustNoOnePeopleFromPacket(event?.detail);
        if (!Array.isArray(people)) return;
        trustNoOneState.latestPeople = people;
        renderTrustNoOneImposters();
    }

    function installTrustNoOneListener() {
        if (trustNoOneState.listenerInstalled) return;
        trustNoOneState.listenerInstalled = true;
        socketManager.addEventListener("blueboatMessage", handleTrustNoOnePacket);
    }

    function startTrustNoOne() {
        trustNoOneState.enabled = true;
        installTrustNoOneListener();
        if (document.body) renderTrustNoOneImposters();
        else window.addEventListener("DOMContentLoaded", renderTrustNoOneImposters, { once: true });
    }

    function stopTrustNoOne() {
        trustNoOneState.enabled = false;
        trustNoOneState.panel?.remove();
        trustNoOneState.panel = null;
        trustNoOneState.status = null;
    }

    const DRAWIT_SKIP = new Set(["DRAW_MODE_LD"]);
    const drawItHookedSockets = new WeakSet();
    let drawItHookInstalled = false;

    function bbDecodeDrawItExact(buffer) {
        try {
            const first = new Uint8Array(buffer)[0];
            if (first >= 0x30 && first <= 0x36) return null;
            function BB(buf) {
                this.t = 0;
                this.i = (buf instanceof ArrayBuffer ? buf : buf.buffer).slice(1);
                this.s = new DataView(this.i);
            }
            BB.prototype.str = function (n) {
                let s = "";
                for (let i = this.t, e = this.t + n; i < e; i++) {
                    let a = this.s.getUint8(i);
                    if (a < 128) s += String.fromCharCode(a);
                    else if ((a & 0xe0) === 0xc0) s += String.fromCharCode((a & 0x1f) << 6 | (this.s.getUint8(++i) & 0x3f));
                    else if ((a & 0xf0) === 0xe0) s += String.fromCharCode((a & 0x0f) << 12 | (this.s.getUint8(++i) & 0x3f) << 6 | (this.s.getUint8(++i) & 0x3f));
                }
                this.t += n;
                return s;
            };
            BB.prototype.arr = function (n) {
                const a = [];
                for (let i = 0; i < n; i++) a.push(this.p());
                return a;
            };
            BB.prototype.map = function (n) {
                const o = {};
                for (let i = 0; i < n; i++) {
                    const k = this.p();
                    o[k] = this.p();
                }
                return o;
            };
            BB.prototype.bin = function (n) {
                const v = this.i.slice(this.t, this.t + n);
                this.t += n;
                return v;
            };
            BB.prototype.p = function () {
                if (this.t >= this.s.byteLength) return undefined;
                const b = this.s.getUint8(this.t++);
                if (b < 0x80) return b;
                if (b < 0x90) return this.map(b & 0x0f);
                if (b < 0xa0) return this.arr(b & 0x0f);
                if (b < 0xc0) return this.str(b & 0x1f);
                if (b > 0xdf) return -(0x100 - b);
                switch (b) {
                    case 0xc0: return null;
                    case 0xc2: return false;
                    case 0xc3: return true;
                    case 0xc4: { const n = this.s.getUint8(this.t); this.t += 1; return this.bin(n); }
                    case 0xca: { const v = this.s.getFloat32(this.t); this.t += 4; return v; }
                    case 0xcb: { const v = this.s.getFloat64(this.t); this.t += 8; return v; }
                    case 0xcc: { const v = this.s.getUint8(this.t); this.t += 1; return v; }
                    case 0xcd: { const v = this.s.getUint16(this.t); this.t += 2; return v; }
                    case 0xce: { const v = this.s.getUint32(this.t); this.t += 4; return v; }
                    case 0xd0: { const v = this.s.getInt8(this.t); this.t += 1; return v; }
                    case 0xd1: { const v = this.s.getInt16(this.t); this.t += 2; return v; }
                    case 0xd2: { const v = this.s.getInt32(this.t); this.t += 4; return v; }
                    case 0xd9: { const n = this.s.getUint8(this.t); this.t += 1; return this.str(n); }
                    case 0xda: { const n = this.s.getUint16(this.t); this.t += 2; return this.str(n); }
                    case 0xdc: { const n = this.s.getUint16(this.t); this.t += 2; return this.arr(n); }
                    case 0xdd: { const n = this.s.getUint32(this.t); this.t += 4; return this.arr(n); }
                    case 0xde: { const n = this.s.getUint16(this.t); this.t += 2; return this.map(n); }
                    case 0xdf: { const n = this.s.getUint32(this.t); this.t += 4; return this.map(n); }
                    default: return `<0x${b.toString(16)}>`;
                }
            };
            const parsed = new BB(buffer).p();
            if (Array.isArray(parsed?.data)) {
                const inner = parsed.data[1];
                return { key: inner?.key ?? parsed.data[0], data: inner?.data ?? inner };
            }
            return parsed ?? null;
        } catch (_) {
            return null;
        }
    }

    function logAnswerCandidatesDrawItExact(stateUpdateData) {
        const rows = Array.isArray(stateUpdateData) ? stateUpdateData : [stateUpdateData];
        for (const row of rows) {
            if (!row || typeof row !== "object") continue;
            if (!Array.isArray(row.value)) continue;
            for (const item of row.value) {
                const directKey = item?.key;
                const nestedKey = item?.value?.key;
                const fieldKey = directKey ?? nestedKey;
                const directValue = item?.value;
                const nestedValue = item?.value?.value;
                const fieldValue = typeof nestedValue === "undefined" ? directValue : nestedValue;
                if (!fieldKey) continue;
                if (fieldKey !== "term") continue;
                if (typeof fieldValue !== "string") continue;
                const answer = fieldValue.trim();
                if (!answer) continue;
                applyDrawItAnswerReveal(answer);
                if (answerPopupState.enabled) showAnswerPopup(answer);
            }
        }
    }


    const lavaBuildingHudState = {
        enabled: false,
        container: null,
        balance: 0,
        config: {
            displayTitle: true,
            hudSize: 100,
        },
    };

    function applyUpgradeLevelsFromStateUpdate(stateUpdateData, source = "unknown") {
        const levels = extractUpgradeLevelsFromStateUpdate(stateUpdateData);
        if (!levels) return false;
        upgradeHudLog(`UPGRADE_LEVELS detected via ${source}`, levels);
        updateUpgradeHudLevels(levels);
        return true;
    }

    function hookSocketDrawIt(ws) {
        if (drawItHookedSockets.has(ws)) return;
        drawItHookedSockets.add(ws);
        ws.addEventListener("message", (e) => {
            const decoded = bbDecodeDrawItExact(e.data);
            if (!decoded?.key) return;
            const key = decoded.key;
            if (DRAWIT_SKIP.has(key)) return;
            if (key === "STATE_UPDATE") {
                logAnswerCandidatesDrawItExact(decoded.data);
                const parsedBalance = extractBalanceFromStateUpdate(decoded.data);
                if (parsedBalance != null) {
                    updateUpgradeHudBalance(parsedBalance);
                    lavaBuildingHudState.balance = parsedBalance;
                    if (lavaBuildingHudState.enabled) renderLavaBuildingHud();
                }
                applyUpgradeLevelsFromStateUpdate(decoded.data, "raw-ws-hook");
            }
        });
    }

    function installDrawItAnswerHook() {
        if (drawItHookInstalled) return;
        drawItHookInstalled = true;
        const originalSend = WebSocket.prototype.send;
        WebSocket.prototype.send = function (data) {
            if (!this.url?.startsWith("ws://localhost")) hookSocketDrawIt(this);
            originalSend.call(this, data);
        };
    }
    installDrawItAnswerHook();

    const autoAnswerState = {
        questions: [],
        answerDeviceId: null,
        currentQuestionId: null,
        questionIdList: [],
        currentQuestionIndex: -1,
    };
    const AUTO_ANSWER_TICK = 1000;
    let autoAnswerEnabled = false;
    let answerInterval = null;

    function answerQuestion() {
        if (socketManager.transportType === "colyseus") {
            if (autoAnswerState.currentQuestionId == null || autoAnswerState.answerDeviceId == null) return;
            const question = autoAnswerState.questions.find((q) => q._id == autoAnswerState.currentQuestionId);
            if (!question) return;
            const packet = { key: "answered", deviceId: autoAnswerState.answerDeviceId, data: {} };
            if (question.type == "text") packet.data.answer = question.answers[0].text;
            else packet.data.answer = question.answers.find((a) => a.correct)?._id;
            if (!packet.data.answer) return;
            socketManager.sendMessage("MESSAGE_FOR_DEVICE", packet);
        } else {
            const questionId = autoAnswerState.questionIdList[autoAnswerState.currentQuestionIndex];
            const question = autoAnswerState.questions.find((q) => q._id == questionId);
            if (!question) return;
            const answer = question.type == "mc" ? question.answers.find((a) => a.correct)?._id : question.answers[0]?.text;
            if (!answer) return;
            socketManager.sendMessage("QUESTION_ANSWERED", { answer, questionId });
        }
    }

    const autoAnswerModule = new Module("Auto Answer", {
        onEnable: () => {
            console.log("Auto Answer enabled");
            autoAnswerEnabled = true;
        },
        onDisable: () => {
            console.log("Auto Answer disabled");
            autoAnswerEnabled = false;
        },
    });

    socketManager.addEventListener("deviceChanges", event => {
        for (const { id, data } of event.detail || []) {
            for (const key in data || {}) {
                if (key === "GLOBAL_questions") {
                    autoAnswerState.questions = JSON.parse(data[key]);
                    autoAnswerState.answerDeviceId = id;
                }
                if (key === `PLAYER_${socketManager.playerId}_currentQuestionId`) {
                    autoAnswerState.currentQuestionId = data[key];
                }
            }
        }
    });

    socketManager.addEventListener("blueboatMessage", event => {
        if (event.detail?.key !== "STATE_UPDATE") return;

        switch (event.detail.data.type) {
            case "GAME_QUESTIONS":
                autoAnswerState.questions = event.detail.data.value;
                break;
            case "PLAYER_QUESTION_LIST":
                autoAnswerState.questionIdList = event.detail.data.value.questionList;
                autoAnswerState.currentQuestionIndex = event.detail.data.value.questionIndex;
                break;
            case "PLAYER_QUESTION_LIST_INDEX":
                autoAnswerState.currentQuestionIndex = event.detail.data.value;
                break;
        }
    });

    const extractDrawItAnswerCandidates = (stateUpdateData) => {
        const rows = Array.isArray(stateUpdateData) ? stateUpdateData : [stateUpdateData];
        const answers = [];
        for (const row of rows) {
            if (!row || typeof row !== "object" || !Array.isArray(row.value)) continue;
            for (const item of row.value) {
                const directKey = item?.key;
                const nestedKey = item?.value?.key;
                const fieldKey = directKey ?? nestedKey;
                const directValue = item?.value;
                const nestedValue = item?.value?.value;
                const fieldValue = typeof nestedValue === "undefined" ? directValue : nestedValue;
                if (fieldKey !== "term" || typeof fieldValue !== "string") continue;
                const answer = fieldValue.trim();
                if (answer) answers.push(answer);
            }
        }
        return answers;
    };

    socketManager.addEventListener("blueboatMessage", (event) => {
        if (event.detail?.key !== "STATE_UPDATE") return;
        const answers = extractDrawItAnswerCandidates(event.detail.data);
        if (!answers.length) return;
        const latestAnswer = answers[answers.length - 1];
        applyDrawItAnswerReveal(latestAnswer);
        if (answerPopupState.enabled) showAnswerPopup(latestAnswer);
    });

    socketManager.addEventListener("blueboatMessage", (event) => {
        const packet = event.detail;
        const key = packet?.key ?? packet?.payload?.key ?? packet?.data?.key;
        const directType = packet?.type ?? packet?.data?.type ?? packet?.payload?.data?.type ?? null;
        if (key !== "STATE_UPDATE" && directType !== "BALANCE" && directType !== "UPGRADE_LEVELS") return;
        const stateUpdate = packet?.data ?? packet?.payload?.data ?? packet?.payload ?? packet;
        const balance = extractBalanceFromStateUpdate(stateUpdate);
        if (balance != null) {
            updateUpgradeHudBalance(balance);
            lavaBuildingHudState.balance = balance;
            if (lavaBuildingHudState.enabled) renderLavaBuildingHud();
            return;
        }
        const applied = applyUpgradeLevelsFromStateUpdate(stateUpdate, "socketManager");
        if (!applied) {
            upgradeHudLog("STATE_UPDATE received but no UPGRADE_LEVELS found", { packet, stateUpdate });
        }
    });

    answerInterval = setInterval(() => {
        if (!autoAnswerEnabled) return;
        answerQuestion();
    }, AUTO_ANSWER_TICK);

    const ESP_LOG = "[ESP]";
    const espState = {
        enabled: false,
        canvas: null,
        ctx: null,
        stores: null,
        storesPromise: null,
        seenPlayers: new Map(),
        waitLogTick: 0,
    };
    const renderDiagnostics = {
        frameCount: 0,
        droppedFrames: 0,
        lastFrameAt: 0,
        moduleMs: {
            esp: 0,
            crosshair: 0,
            autoAim: 0,
            triggerAssist: 0,
        },
    };
    const unifiedRenderState = {
        rafId: null,
        running: false,
    };
    const cameraZoomState = {
        enabled: false,
        originalZoom: null,
        cameraRef: null,
        baselineByCamera: new WeakMap(),
        toastTimeoutId: null,
        toastEl: null,
        lastToastValue: null,
    };
    const CAMERA_ZOOM_MODULE_NAME = "Zoom (FOV)";
    const CAMERA_ZOOM_MIN = 0.3;
    const CAMERA_ZOOM_MAX = 2.0;
    const CAMERA_ZOOM_STEP = 0.05;
    const CAMERA_ZOOM_DEFAULT = 0.8;

    function espLog(message, extra) {
        if (extra !== undefined) console.log(`${ESP_LOG} ${message}`, extra);
        else console.log(`${ESP_LOG} ${message}`);
    }

    function createEspCanvas() {
        if (espState.canvas?.parentNode) {
            espLog("Canvas already exists; reusing existing canvas.");
            return;
        }
        const canvas = document.createElement("canvas");
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        canvas.style.position = "fixed";
        canvas.style.left = "0";
        canvas.style.top = "0";
        canvas.style.width = "100vw";
        canvas.style.height = "100vh";
        canvas.style.zIndex = "9999";
        canvas.style.pointerEvents = "none";
        canvas.style.userSelect = "none";
        document.body.appendChild(canvas);
        espState.canvas = canvas;
        espState.ctx = canvas.getContext("2d");
        if (!espState.ctx) {
            espLog("Failed to get canvas 2D context");
            canvas.remove();
            espState.canvas = null;
            return;
        }
        espLog("Canvas created");
    }

    function destroyEspCanvas() {
        if (!espState.canvas) return;
        espState.canvas.remove();
        espState.canvas = null;
        espState.ctx = null;
        espLog("Canvas destroyed");
    }

    function resizeEspCanvas() {
        if (!espState.canvas?.parentNode) return;
        espState.canvas.width = window.innerWidth;
        espState.canvas.height = window.innerHeight;
        espLog(`Canvas resized to ${espState.canvas.width}x${espState.canvas.height}`);
    }

    function clampCameraZoom(value) {
        return Math.min(CAMERA_ZOOM_MAX, Math.max(CAMERA_ZOOM_MIN, Number(value) || CAMERA_ZOOM_DEFAULT));
    }

    function resolvePrimaryCamera() {
        return window?.stores?.phaser?.scene?.cameras?.cameras?.[0] || null;
    }

    function ensureCameraZoomToast() {
        if (cameraZoomState.toastEl?.isConnected) return cameraZoomState.toastEl;
        const toast = document.createElement("div");
        toast.style.cssText = "position:fixed;left:50%;bottom:36px;transform:translate(-50%,8px);background:rgba(8,12,20,.82);border:1px solid rgba(255,255,255,.22);color:#fff;padding:6px 10px;border-radius:8px;font:600 12px Inter,system-ui,sans-serif;z-index:2147483647;opacity:0;pointer-events:none;transition:opacity .15s ease,transform .15s ease;";
        document.documentElement.appendChild(toast);
        cameraZoomState.toastEl = toast;
        return toast;
    }

    function showCameraZoomToast(zoomValue) {
        const rounded = Math.round(clampCameraZoom(zoomValue) * 100) / 100;
        if (cameraZoomState.lastToastValue === rounded) return;
        cameraZoomState.lastToastValue = rounded;
        const toast = ensureCameraZoomToast();
        toast.textContent = `Zoom: ${rounded.toFixed(2)}x`;
        toast.style.opacity = "1";
        toast.style.transform = "translate(-50%,0)";
        if (cameraZoomState.toastTimeoutId) clearTimeout(cameraZoomState.toastTimeoutId);
        cameraZoomState.toastTimeoutId = setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translate(-50%,8px)";
        }, 900);
    }

    function applyCameraZoomTick() {
        const cfgStore = state?.moduleConfig instanceof Map ? state.moduleConfig : null;
        const cfg = (cfgStore?.get(CAMERA_ZOOM_MODULE_NAME) && typeof cfgStore.get(CAMERA_ZOOM_MODULE_NAME) === "object")
            ? cfgStore.get(CAMERA_ZOOM_MODULE_NAME)
            : { zoom: CAMERA_ZOOM_DEFAULT };
        const desiredZoom = clampCameraZoom(cfg.zoom ?? CAMERA_ZOOM_DEFAULT);
        if (Number(cfg.zoom) !== desiredZoom) cfg.zoom = desiredZoom;
        const camera = resolvePrimaryCamera();
        if (!camera) return;
        if (camera !== cameraZoomState.cameraRef) {
            cameraZoomState.cameraRef = camera;
            const baselineZoom = Number(camera?.zoom ?? 1);
            if (Number.isFinite(baselineZoom) && baselineZoom > 0) {
                cameraZoomState.originalZoom = baselineZoom;
                cameraZoomState.baselineByCamera.set(camera, baselineZoom);
            } else {
                cameraZoomState.originalZoom = 1;
            }
        }
        const baselineZoomRaw = cameraZoomState.baselineByCamera.get(camera);
        const baselineZoom = Number.isFinite(baselineZoomRaw) && baselineZoomRaw > 0 ? baselineZoomRaw : Number(camera?.zoom ?? 1) || 1;
        const targetZoom = baselineZoom * desiredZoom;
        const currentZoom = Number(camera?.zoom ?? 1) || 1;
        if (Math.abs(currentZoom - targetZoom) > 1e-4) {
            if (typeof camera?.setZoom === "function") camera.setZoom(targetZoom);
            else camera.zoom = targetZoom;
        }
    }

    function startCameraZoom() {
        if (cameraZoomState.enabled) return;
        cameraZoomState.enabled = true;
        cameraZoomState.cameraRef = null;
        cameraZoomState.originalZoom = null;
        cameraZoomState.lastToastValue = null;
        startUnifiedRenderLoop();
    }

    function hideCameraZoomToast() {
        if (cameraZoomState.toastTimeoutId) {
            clearTimeout(cameraZoomState.toastTimeoutId);
            cameraZoomState.toastTimeoutId = null;
        }
        if (cameraZoomState.toastEl?.isConnected) {
            cameraZoomState.toastEl.style.opacity = "0";
            cameraZoomState.toastEl.style.transform = "translate(-50%,8px)";
        }
    }

    function stopCameraZoom() {
        if (!cameraZoomState.enabled) return;
        cameraZoomState.enabled = false;
        hideCameraZoomToast();
        const camera = resolvePrimaryCamera();
        const restoreZoom = Number(
            camera && cameraZoomState.baselineByCamera.has(camera)
                ? cameraZoomState.baselineByCamera.get(camera)
                : cameraZoomState.originalZoom,
        );
        if (camera === cameraZoomState.cameraRef && Number.isFinite(restoreZoom) && restoreZoom > 0.2 && restoreZoom < 5) {
            const currentZoom = Number(camera.zoom ?? 1) || 1;
            if (Math.abs(currentZoom - restoreZoom) > 1e-4) {
                if (typeof camera?.setZoom === "function") camera.setZoom(restoreZoom);
                else camera.zoom = restoreZoom;
            }
        }
        cameraZoomState.originalZoom = null;
        cameraZoomState.cameraRef = null;
        stopUnifiedRenderLoopIfIdle();
    }

    async function resolveEspStores() {
        if (espState.stores) return espState.stores;
        if (espState.storesPromise) return espState.storesPromise;
        espState.storesPromise = (async () => {
            if (!document.body) {
                await new Promise((resolve) => window.addEventListener("DOMContentLoaded", resolve, { once: true }));
            }
            const moduleScript = document.querySelector("script[src][type='module']");
            if (!moduleScript?.src) throw new Error("Failed to find game module script");

            const response = await fetch(moduleScript.src);
            const text = await response.text();
            const gameScriptUrl = text.match(/FixSpinePlugin-[^.]+\.js/)?.[0];
            if (!gameScriptUrl) throw new Error("Failed to find game script URL");

            const gameScript = await import(`/assets/${gameScriptUrl}`);
            const stores = Object.values(gameScript).find((value) => value && value.assignment);
            if (!stores) throw new Error("Failed to resolve stores export");

            window.stores = stores;
            espState.stores = stores;
            espLog("Resolved stores via module import");
            return stores;
        })();
        try {
            return await espState.storesPromise;
        } finally {
            espState.storesPromise = null;
        }
    }

    function primeSharedPlayerData() {
        if (espState.stores || espState.storesPromise) return;
        const attemptResolve = () => {
            resolveEspStores().catch((error) => {
                espLog("Shared stores resolve failed; retrying", error);
                setTimeout(() => {
                    if (!espState.stores) attemptResolve();
                }, 1500);
            });
        };
        attemptResolve();
    }

    primeSharedPlayerData();

    function getCharacterPosition(character) {
        const x = Number(character?.x ?? character?.position?.x ?? character?.body?.x);
        const y = Number(character?.y ?? character?.position?.y ?? character?.body?.y);
        if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
        return { x, y };
    }

    function getCharacters(stores) {
        const manager = stores?.phaser?.scene?.characterManager;
        const map = manager?.characters;
        if (!map) return [];
        if (typeof map.values === "function") return Array.from(map.values());
        if (Array.isArray(map)) return map;
        return Object.values(map);
    }

    function getCharacterEntries(stores) {
        const manager = stores?.phaser?.scene?.characterManager;
        const map = manager?.characters;
        if (!map) return [];
        if (typeof map.entries === "function") {
            return Array.from(map.entries(), ([id, character]) => ({ id, character }));
        }
        if (Array.isArray(map)) {
            return map.map((character, index) => ({ id: character?.id ?? character?.characterId ?? index, character }));
        }
        return Object.entries(map).map(([id, character]) => ({ id, character }));
    }

    function getMainCharacter(stores) {
        const mainId = stores?.phaser?.mainCharacter?.id;
        const manager = stores?.phaser?.scene?.characterManager;
        const map = manager?.characters;
        if (!map) return null;
        if (mainId != null && typeof map.get === "function") return map.get(mainId) || null;
        return getCharacters(stores).find((character) => character?.id === mainId || character?.characterId === mainId) || null;
    }

    function getCharacterTeam(character) {
        return character?.teamId ?? character?.team?.id ?? character?.state?.teamId ?? character?.data?.teamId ?? null;
    }

    function getCharacterId(character) {
        return character?.id ?? character?.characterId ?? character?.playerId ?? character?.entityId ?? null;
    }

    function getSerializerCharacterById(id) {
        if (id == null) return null;
        const map = window?.serializer?.state?.characters?.$items;
        if (!map || typeof map.get !== "function") return null;
        return map.get(id) || map.get(String(id)) || null;
    }

    function findSerializerCharacterByPosition(character) {
        const map = window?.serializer?.state?.characters?.$items;
        if (!map || typeof map.values !== "function") return null;
        const x = Number(character?.x ?? character?.position?.x);
        const y = Number(character?.y ?? character?.position?.y);
        if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
        for (const candidate of map.values()) {
            const cx = Number(candidate?.x ?? candidate?.position?.x);
            const cy = Number(candidate?.y ?? candidate?.position?.y);
            if (!Number.isFinite(cx) || !Number.isFinite(cy)) continue;
            if (Math.abs(cx - x) < 0.5 && Math.abs(cy - y) < 0.5) return candidate;
        }
        return null;
    }

    function getCharacterName(character, fallbackId = null) {
        const id = getCharacterId(character) ?? fallbackId;
        const serializerCharacter = getSerializerCharacterById(id) ?? findSerializerCharacterByPosition(character);
        return character?.name
            ?? character?.nametag?.name
            ?? character?.displayName
            ?? character?.state?.name
            ?? character?.state?.nametag?.name
            ?? character?.username
            ?? character?.playerName
            ?? character?.profile?.name
            ?? character?.meta?.name
            ?? character?.data?.name
            ?? character?.data?.nametag?.name
            ?? serializerCharacter?.name
            ?? serializerCharacter?.nametag?.name
            ?? serializerCharacter?.displayName
            ?? serializerCharacter?.username
            ?? "Player";
    }

    function formatEspLabel(playerName, distance, namesDistanceOnly, style) {
        const safeName = String(playerName || "Player");
        const distanceText = `${Math.floor(Number(distance) || 0)}m`;
        const showName = namesDistanceOnly?.showName !== undefined ? namesDistanceOnly.showName : true;
        const showDistance = namesDistanceOnly?.showDistance !== undefined ? namesDistanceOnly.showDistance : true;
        if (!showName && !showDistance) return "";
        if (showName && !showDistance) return safeName;
        if (!showName && showDistance) return distanceText;
        switch (style) {
            case "dash":
                return `${safeName} - ${distanceText}`;
            case "pipe":
                return `${safeName} | ${distanceText}`;
            case "distanceFirst":
                return `${distanceText} • ${safeName}`;
            case "paren":
                return `${safeName} (${distanceText})`;
            case "dot":
            default:
                return `${safeName} • ${distanceText}`;
        }
    }

    function resolveNameDistanceVisibility(cfg, isTeammate) {
        const nameKey = isTeammate ? "teammateNameTextEnabled" : "nameTextEnabled";
        const distanceKey = isTeammate ? "teammateDistanceTextEnabled" : "distanceTextEnabled";
        const explicitName = cfg?.[nameKey];
        const explicitDistance = cfg?.[distanceKey];
        if (typeof explicitName === "boolean" || typeof explicitDistance === "boolean") {
            return {
                showName: explicitName !== false,
                showDistance: explicitDistance !== false,
            };
        }
        const legacyNamesEnabled = isTeammate ? (cfg?.teammateNames !== false) : (cfg?.names !== false);
        const legacyDistanceOnly = isTeammate ? (cfg?.teammateNamesDistanceOnly === true) : (cfg?.namesDistanceOnly === true);
        if (!legacyNamesEnabled) return { showName: false, showDistance: false };
        if (legacyDistanceOnly) return { showName: false, showDistance: true };
        return { showName: true, showDistance: true };
    }

    function projectWorldToScreen(position, cameraSnapshot, viewportWidth, viewportHeight) {
        const x = Number(position?.x);
        const y = Number(position?.y);
        const camX = Number(cameraSnapshot?.midX);
        const camY = Number(cameraSnapshot?.midY);
        const zoom = Number(cameraSnapshot?.zoom ?? 1) || 1;
        if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(camX) || !Number.isFinite(camY)) return null;
        return {
            x: (x - camX) * zoom + viewportWidth / 2,
            y: (y - camY) * zoom + viewportHeight / 2,
            zoom,
        };
    }

    function getEspRenderConfig() {
        const defaults = {
            showEnemies: true,
            showTeammates: true,
            hitbox: true,
            hitboxSize: 150,
            hitboxWidth: 3,
            hitboxColor: "#ff4444",
            teammateHitbox: true,
            teammateHitboxSize: 150,
            teammateHitboxWidth: 3,
            teammateHitboxColor: "#36d17c",
            names: true,
            namesDistanceOnly: false,
            nameTextEnabled: true,
            distanceTextEnabled: true,
            nameSize: 22,
            nameColor: "#7a0c0c",
            nameOutline: true,
            nameOutlineColor: "#000000",
            nameOutlineWidth: 1,
            nameDistanceStyle: "dot",
            teammateNames: true,
            teammateNamesDistanceOnly: false,
            teammateNameTextEnabled: true,
            teammateDistanceTextEnabled: true,
            teammateNameSize: 22,
            teammateNameColor: "#baf7d2",
            teammateNameOutline: true,
            teammateNameOutlineColor: "#ffffff",
            teammateNameOutlineWidth: 1,
            teammateNameDistanceStyle: "dot",
            offscreenStyle: "tracers",
            offscreenTheme: "classic",
            alwaysTracer: false,
            tracerWidth: 3,
            tracerColor: "#ff4444",
            teammateOffscreenStyle: "tracers",
            teammateOffscreenTheme: "classic",
            teammateAlwaysTracer: false,
            teammateTracerWidth: 3,
            teammateTracerColor: "#36d17c",
            arrowSize: 14,
            arrowColor: "#ff4444",
            teammateArrowSize: 14,
            teammateArrowColor: "#36d17c",
            arrowStyle: "regular",
            teammateArrowStyle: "regular",
            valueTextColor: window.__zyroxEspValueTextColor || "#ffffff",
        };
        const liveCfg = window.__zyroxEspConfig;
        if (liveCfg && typeof liveCfg === "object") return { ...defaults, ...liveCfg };
        return defaults;
    }

    function getHealthBarsConfig() {
        const defaults = {
            enabled: true,
            width: 54,
            height: 6,
            yOffset: 32,
            showText: true,
        };
        const liveCfg = window.__zyroxHealthBarsConfig;
        return liveCfg && typeof liveCfg === "object" ? { ...defaults, ...liveCfg } : defaults;
    }

    function readNumericCandidate(source, paths) {
        if (!source) return null;
        for (const path of paths) {
            const parts = path.split(".");
            let node = source;
            for (const part of parts) node = node?.[part];
            const value = Number(node);
            if (Number.isFinite(value)) return value;
        }
        return null;
    }

    function getCharacterHealthSnapshot(character, fallbackId = null) {
        const cid = getCharacterId(character) ?? fallbackId;
        const serializerCharacter = getSerializerCharacterById(cid) ?? findSerializerCharacterByPosition(character);
        const candidates = [character, serializerCharacter];
        let current = null;
        let max = null;
        for (const source of candidates) {
            if (!source) continue;
            if (current == null) {
                current = readNumericCandidate(source, ["health", "hp", "currentHealth", "state.health", "stats.health", "data.health"]);
            }
            if (max == null) {
                max = readNumericCandidate(source, ["maxHealth", "maxHp", "healthMax", "state.maxHealth", "stats.maxHealth", "data.maxHealth"]);
            }
            if (current != null && max != null) break;
        }
        if (current == null) return null;
        if (max == null || max <= 0) {
            if (current <= 100) max = 100;
            else return null;
        }
        return { current: Math.max(0, current), max: Math.max(1, max) };
    }

    function renderEspPlayers(stores) {
        const ctx = espState.ctx;
        const canvas = espState.canvas;
        if (!ctx || !canvas) {
            espLog("Missing data: no canvas/context; rendering skip.");
            return;
        }
        const camera = stores?.phaser?.scene?.cameras?.cameras?.[0];
        const me = getMainCharacter(stores);
        if (!camera || !me) {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            return;
        }
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const myTeam = getCharacterTeam(me);
        const espCfg = getEspRenderConfig();
        const healthCfg = getHealthBarsConfig();
        const showHealthBars = state.enabledModules?.has("Health Bars") && healthCfg.enabled !== false;
        const camX = Number(camera?.midPoint?.x);
        const camY = Number(camera?.midPoint?.y);
        const zoom = Number(camera?.zoom ?? 1) || 1;
        if (!Number.isFinite(camX) || !Number.isFinite(camY)) return;

        const activeIds = new Set();
        const now = performance.now();

        for (const entry of getCharacterEntries(stores)) {
            const character = entry.character;
            const characterId = entry.id ?? getCharacterId(character);
            if (!character || character === me) continue;
            const pos = getCharacterPosition(character);
            if (!pos) continue;
            const stableId = String(characterId ?? `${Math.round(pos.x)}:${Math.round(pos.y)}`);
            activeIds.add(stableId);
            const angle = Math.atan2(pos.y - camY, pos.x - camX);
            const worldDistance = Math.hypot(pos.x - camX, pos.y - camY);
            const screenDistance = worldDistance * zoom;
            const rawX = (pos.x - camX) * zoom + canvas.width / 2;
            const rawY = (pos.y - camY) * zoom + canvas.height / 2;
            const prev = espState.seenPlayers.get(stableId);
            let screenX = rawX;
            let screenY = rawY;
            if (prev) {
                const delta = Math.hypot(rawX - prev.x, rawY - prev.y);
                if (delta < 300) {
                    const blend = 0.38;
                    screenX = prev.x + (rawX - prev.x) * blend;
                    screenY = prev.y + (rawY - prev.y) * blend;
                }
            }
            espState.seenPlayers.set(stableId, { x: screenX, y: screenY, t: now });
            const onScreen = screenX >= 0 && screenX <= canvas.width && screenY >= 0 && screenY <= canvas.height;
            const isTeammate = myTeam !== null && getCharacterTeam(character) === myTeam;
            if (isTeammate && espCfg.showTeammates === false) continue;
            if (!isTeammate && espCfg.showEnemies === false) continue;
            const showHitbox = isTeammate ? espCfg.teammateHitbox !== false : espCfg.hitbox !== false;
            const nameDistanceVisibility = resolveNameDistanceVisibility(espCfg, isTeammate);
            const chosenDistanceStyle = isTeammate ? espCfg.teammateNameDistanceStyle : espCfg.nameDistanceStyle;
            const distanceStyle = ["dot", "dash", "pipe", "paren", "distanceFirst"].includes(chosenDistanceStyle)
                ? chosenDistanceStyle
                : "dot";
            const chosenOffscreenStyle = isTeammate ? espCfg.teammateOffscreenStyle : espCfg.offscreenStyle;
            const offscreenStyle = chosenOffscreenStyle === "arrows" || chosenOffscreenStyle === "none"
                ? chosenOffscreenStyle
                : "tracers";
            const offscreenTheme = String(isTeammate ? espCfg.teammateOffscreenTheme : espCfg.offscreenTheme || "classic");
            const alwaysTracer = isTeammate ? espCfg.teammateAlwaysTracer === true : espCfg.alwaysTracer === true;
            const chosenArrowStyle = isTeammate ? espCfg.teammateArrowStyle : espCfg.arrowStyle;
            const arrowStyle = ["regular", "dot", "modern"].includes(chosenArrowStyle) ? chosenArrowStyle : "regular";
            const hitboxColor = isTeammate
                ? (espCfg.teammateHitboxColor || espCfg.hitboxColor || "green")
                : (espCfg.hitboxColor || "red");
            const tracerColor = isTeammate
                ? (espCfg.teammateTracerColor || espCfg.tracerColor || "green")
                : (espCfg.tracerColor || "red");
            const arrowColor = isTeammate
                ? (espCfg.teammateArrowColor || espCfg.arrowColor || "green")
                : (espCfg.arrowColor || "red");
            const nameColor = isTeammate
                ? (espCfg.teammateNameColor || espCfg.nameColor || "#000000")
                : (espCfg.nameColor || "#000000");
            const nameOutlineEnabled = isTeammate ? espCfg.teammateNameOutline !== false : espCfg.nameOutline !== false;
            const nameOutlineColor = isTeammate
                ? (espCfg.teammateNameOutlineColor || espCfg.nameOutlineColor || "#000000")
                : (espCfg.nameOutlineColor || "#000000");
            const hitboxSize = Math.max(12, Number(isTeammate ? espCfg.teammateHitboxSize : espCfg.hitboxSize) || 80);
            const hitboxWidth = Math.max(1, Number(isTeammate ? espCfg.teammateHitboxWidth : espCfg.hitboxWidth) || 3);
            const nameSize = Math.max(8, Number(isTeammate ? espCfg.teammateNameSize : espCfg.nameSize) || 20);
            const nameOutlineWidth = Math.max(1, Number(isTeammate ? espCfg.teammateNameOutlineWidth : espCfg.nameOutlineWidth) || 3);
            const tracerWidth = Math.max(1, Number(isTeammate ? espCfg.teammateTracerWidth : espCfg.tracerWidth) || 3);
            const arrowSize = Math.max(6, Number(isTeammate ? espCfg.teammateArrowSize : espCfg.arrowSize) || 14);

            if (onScreen && showHitbox) {
                const boxSize = Math.max(24, hitboxSize * zoom);
                ctx.beginPath();
                ctx.lineWidth = hitboxWidth;
                ctx.strokeStyle = hitboxColor;
                ctx.strokeRect(screenX - boxSize / 2, screenY - boxSize / 2, boxSize, boxSize);
            }

            const shouldDrawOffscreen = !onScreen && offscreenStyle !== "none";
            const shouldDrawTracer = offscreenStyle === "tracers" && (alwaysTracer || !onScreen);

            let labelX = onScreen ? screenX : Math.cos(angle) * Math.min(250, screenDistance) + canvas.width / 2;
            let labelY = onScreen ? (screenY - 18) : Math.sin(angle) * Math.min(250, screenDistance) + canvas.height / 2;

            if (shouldDrawOffscreen || shouldDrawTracer) {
                const margin = 20;
                const halfW = canvas.width / 2 - margin;
                const halfH = canvas.height / 2 - margin;
                const dx = Math.cos(angle);
                const dy = Math.sin(angle);
                const scale = Math.min(
                    Math.abs(halfW / (dx || 0.0001)),
                    Math.abs(halfH / (dy || 0.0001))
                );
                const endX = canvas.width / 2 + dx * scale;
                const endY = canvas.height / 2 + dy * scale;

                if (shouldDrawTracer) {
                    ctx.save();
                    ctx.beginPath();
                    ctx.moveTo(canvas.width / 2, canvas.height / 2);
                    ctx.lineTo(onScreen ? screenX : endX, onScreen ? screenY : endY);
                    ctx.lineWidth = tracerWidth;
                    ctx.strokeStyle = tracerColor;
                    if (offscreenTheme === "dashed") ctx.setLineDash([8, 6]);
                    if (offscreenTheme === "neon") {
                        ctx.shadowColor = tracerColor;
                        ctx.shadowBlur = 10;
                    }
                    ctx.stroke();
                    ctx.restore();
                } else if (offscreenStyle === "arrows" && !onScreen) {
                    const headLength = arrowSize;
                    const headAngle = Math.PI / 6;
                    const a1 = angle - headAngle;
                    const a2 = angle + headAngle;
                    ctx.save();
                    ctx.beginPath();
                    if (arrowStyle === "dot") {
                        ctx.arc(endX, endY, Math.max(4, headLength * 0.35), 0, Math.PI * 2);
                        ctx.fillStyle = arrowColor;
                    } else if (arrowStyle === "modern") {
                        const tailX = endX - Math.cos(angle) * headLength;
                        const tailY = endY - Math.sin(angle) * headLength;
                        const perpX = Math.cos(angle + Math.PI / 2) * (headLength * 0.45);
                        const perpY = Math.sin(angle + Math.PI / 2) * (headLength * 0.45);
                        ctx.moveTo(endX, endY);
                        ctx.quadraticCurveTo(tailX + perpX, tailY + perpY, tailX, tailY);
                        ctx.quadraticCurveTo(tailX - perpX, tailY - perpY, endX, endY);
                        ctx.fillStyle = arrowColor;
                    } else {
                        ctx.moveTo(endX, endY);
                        ctx.lineTo(endX - Math.cos(a1) * headLength, endY - Math.sin(a1) * headLength);
                        ctx.moveTo(endX, endY);
                        ctx.lineTo(endX - Math.cos(a2) * headLength, endY - Math.sin(a2) * headLength);
                    }
                    ctx.lineWidth = tracerWidth;
                    ctx.strokeStyle = arrowColor;
                    if (offscreenTheme === "dashed") ctx.setLineDash([6, 5]);
                    if (offscreenTheme === "neon") {
                        ctx.shadowColor = arrowColor;
                        ctx.shadowBlur = 10;
                    }
                    if (arrowStyle === "dot" || arrowStyle === "modern") ctx.fill();
                    else ctx.stroke();
                    ctx.restore();
                    labelX = endX;
                    labelY = endY - Math.max(16, headLength * 1.2);
                }
            }

            if (!nameDistanceVisibility.showName && !nameDistanceVisibility.showDistance) continue;
            ctx.fillStyle = nameColor;
            ctx.font = `${nameSize}px ${espCfg.font || "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"}`;
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            const labelText = formatEspLabel(getCharacterName(character, characterId), worldDistance, nameDistanceVisibility, distanceStyle);
            const textWidth = Math.max(1, ctx.measureText(labelText).width);
            const pad = Math.max(8, nameSize * 0.35);
            const halfText = textWidth / 2;
            const drawX = Math.min(canvas.width - halfText - pad, Math.max(halfText + pad, labelX));
            const drawY = Math.min(canvas.height - nameSize - pad, Math.max(nameSize * 0.7 + pad, labelY));
            if (nameOutlineEnabled) {
                ctx.lineWidth = nameOutlineWidth;
                ctx.strokeStyle = nameOutlineColor;
                ctx.lineJoin = "round";
                ctx.strokeText(labelText, drawX, drawY);
            }
            ctx.fillText(labelText, drawX, drawY);

        }

        for (const [id, data] of espState.seenPlayers) {
            if (!activeIds.has(id) && now - Number(data?.t ?? 0) > 900) {
                espState.seenPlayers.delete(id);
            }
        }
    }

    function renderEspTick() {
        if (!espState.enabled || !espState.ctx || !espState.canvas) return;
        const stores = espState.stores ?? window.stores;
        if (!stores) {
            espState.waitLogTick += 1;
            if (espState.waitLogTick % 60 === 0) espLog("Waiting for stores...");
            espState.ctx.clearRect(0, 0, espState.canvas.width, espState.canvas.height);
            return;
        }
        espState.waitLogTick = 0;
        renderEspPlayers(stores);
    }

    function startEsp() {
        if (espState.enabled) {
            espLog("ESP already enabled; skipping duplicate start.");
            return;
        }
        espState.enabled = true;
        espLog("ESP initialized");
        createEspCanvas();
        resizeEspCanvas();
        resolveEspStores().catch((error) => espLog("Failed to resolve stores", error));
        startUnifiedRenderLoop();
    }

    function stopEsp() {
        if (!espState.enabled) {
            espLog("ESP already disabled; skipping duplicate stop.");
            return;
        }
        espState.enabled = false;
        espState.seenPlayers.clear();
        destroyEspCanvas();
        stopUnifiedRenderLoopIfIdle();
        espLog("ESP stopped and cleaned up");
    }

    window.addEventListener("resize", resizeEspCanvas);

    // ---------------------------------------------------------------------------
    // CROSSHAIR MODULE
    // Renders a crosshair at the mouse cursor position and optionally a line
    // from the center of the screen to the cursor.
    // ---------------------------------------------------------------------------
    const crosshairState = {
        enabled: false,
        canvas: null,
        ctx: null,
        mouseX: 0,
        mouseY: 0,
        rafId: null,
        hidNativeCursor: false,
        previousCursor: "",
    };

    function getCrosshairConfig() {
        const defaults = {
            enabled: true,
            style: "x",
            color: "#ff3b3b",
            crosshairSize: 25,
            lineSize: 4,
            showLine: false,
            lineColor: "#ff3b3b",
            tracerLineSize: 1.5,
            hoverHighlight: true,
            hoverColor: "#ffff00",
            showCrosshairGlyph: true,
        };
        const stored = window.__zyroxCrosshairConfig;
        return stored && typeof stored === "object" ? { ...defaults, ...stored } : defaults;
    }

    function createCrosshairCanvas() {
        if (crosshairState.canvas?.parentNode) return;
        const canvas = document.createElement("canvas");
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        canvas.style.cssText = "position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:10000;pointer-events:none;user-select:none;";
        document.body.appendChild(canvas);
        crosshairState.canvas = canvas;
        crosshairState.ctx = canvas.getContext("2d");
    }

    function destroyCrosshairCanvas() {
        if (crosshairState.rafId != null) { cancelAnimationFrame(crosshairState.rafId); crosshairState.rafId = null; }
        crosshairState.canvas?.remove();
        crosshairState.canvas = null;
        crosshairState.ctx = null;
    }

    function setNativeCursorHidden(hidden) {
        const target = document.body || document.documentElement;
        if (!target) return;
        if (hidden) {
            if (crosshairState.hidNativeCursor) return;
            crosshairState.previousCursor = target.style.cursor || "";
            target.style.cursor = "none";
            crosshairState.hidNativeCursor = true;
            return;
        }
        if (!crosshairState.hidNativeCursor) return;
        target.style.cursor = crosshairState.previousCursor || "";
        crosshairState.previousCursor = "";
        crosshairState.hidNativeCursor = false;
    }

    function disableCrosshairModuleFromEscape() {
        if (!crosshairState.enabled) return;
        const module = state?.modules?.get?.("Crosshair");
        const item = state?.moduleItems?.get?.("Crosshair");
        if (module?.enabled) {
            module.disable();
            item?.classList?.remove("active");
            state?.enabledModules?.delete?.("Crosshair");
            saveSettings();
            return;
        }
        stopCrosshair();
    }

    function shouldIgnoreCrosshairEscapeDisable() {
        if (state?.visible) return true;
        if (state?.listeningForMenuBind || state?.listeningForBind) return true;
        const modal = document.querySelector(".zyrox-config-backdrop");
        if (modal && !modal.classList.contains("hidden")) return true;
        return false;
    }

    function resizeCrosshairCanvas() {
        if (!crosshairState.canvas) return;
        crosshairState.canvas.width = window.innerWidth;
        crosshairState.canvas.height = window.innerHeight;
    }

    function renderCrosshairFrame() {
        if (!crosshairState.enabled) return;
        const ctx = crosshairState.ctx;
        const canvas = crosshairState.canvas;
        if (!ctx || !canvas) return;
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const cfg = getCrosshairConfig();
        if (!cfg.enabled) return;

        const mx = crosshairState.mouseX;
        const my = crosshairState.mouseY;
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;

        const crosshairSize = typeof cfg.crosshairSize === "number" ? cfg.crosshairSize : 25;
        const lineSize = typeof cfg.lineSize === "number" ? cfg.lineSize : 4;
        const tracerSize = typeof cfg.tracerLineSize === "number" ? cfg.tracerLineSize : 1.5;

        // --- Player hover detection ---
        let hoveringPlayer = false;
        if (cfg.hoverHighlight) {
            try {
                const stores = espState.stores ?? window.stores ?? null;
                const camera = stores?.phaser?.scene?.cameras?.cameras?.[0];
                const me = stores ? getMainCharacter(stores) : null;
                if (camera && me) {
                    const camX = Number(camera?.midPoint?.x);
                    const camY = Number(camera?.midPoint?.y);
                    const zoom = Number(camera?.zoom ?? 1) || 1;
                    const hitRadius = (Math.max(20, 120 * zoom) / 2) * 3;
                    if (Number.isFinite(camX) && Number.isFinite(camY)) {
                        for (const { character } of getCharacterEntries(stores)) {
                            if (!character || character === me) continue;
                            const pos = getCharacterPosition(character);
                            if (!pos) continue;
                            const sx = (pos.x - camX) * zoom + canvas.width / 2;
                            const sy = (pos.y - camY) * zoom + canvas.height / 2;
                            if (Math.hypot(mx - sx, my - sy) <= hitRadius) {
                                hoveringPlayer = true;
                                break;
                            }
                        }
                    }
                }
            } catch (_) { /* stores not ready yet */ }
        }

        const col = hoveringPlayer ? (cfg.hoverColor || "#ffff00") : (cfg.color || "#ff3b3b");

        // Draw line from center to cursor if enabled
        if (cfg.showLine) {
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.lineTo(mx, my);
            ctx.lineWidth = tracerSize;
            ctx.strokeStyle = cfg.lineColor || "#ff3b3b";
            ctx.globalAlpha = 0.65;
            ctx.stroke();
            ctx.restore();
        }

        // Draw crosshair at cursor
        if (!cfg.showCrosshairGlyph) return;
        ctx.save();
        ctx.strokeStyle = col;
        ctx.fillStyle = col;
        ctx.lineWidth = lineSize;
        ctx.globalAlpha = 0.92;
        const style = cfg.style || "cross";

        if (style === "dot") {
            ctx.beginPath();
            ctx.arc(mx, my, Math.max(1, crosshairSize * 0.35), 0, Math.PI * 2);
            ctx.fill();
        } else if (style === "solid") {
            // Solid cross — lines go straight through the center with no gap
            const arm = crosshairSize;
            ctx.beginPath();
            ctx.moveTo(mx - arm, my); ctx.lineTo(mx + arm, my);
            ctx.moveTo(mx, my - arm); ctx.lineTo(mx, my + arm);
            ctx.stroke();
        } else if (style === "crossdot") {
            // Cross with gap + filled center dot
            const arm = crosshairSize;
            const gap = Math.max(1, crosshairSize * 0.4);
            ctx.beginPath();
            ctx.moveTo(mx - arm, my); ctx.lineTo(mx - gap, my);
            ctx.moveTo(mx + gap, my); ctx.lineTo(mx + arm, my);
            ctx.moveTo(mx, my - arm); ctx.lineTo(mx, my - gap);
            ctx.moveTo(mx, my + gap); ctx.lineTo(mx, my + arm);
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(mx, my, Math.max(1.5, lineSize * 1.2), 0, Math.PI * 2);
            ctx.fill();
        } else if (style === "circle") {
            ctx.beginPath();
            ctx.arc(mx, my, crosshairSize, 0, Math.PI * 2);
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(mx, my, Math.max(1, crosshairSize * 0.2), 0, Math.PI * 2);
            ctx.fill();
        } else if (style === "circlecross") {
            // Circle with solid cross lines through the center
            ctx.beginPath();
            ctx.arc(mx, my, crosshairSize, 0, Math.PI * 2);
            ctx.stroke();
            const arm = crosshairSize;
            ctx.beginPath();
            ctx.moveTo(mx - arm, my); ctx.lineTo(mx + arm, my);
            ctx.moveTo(mx, my - arm); ctx.lineTo(mx, my + arm);
            ctx.stroke();
        } else if (style === "plus") {
            // Thick plus sign
            ctx.lineWidth = lineSize * 1.5;
            const arm = crosshairSize;
            const gap = Math.max(1, crosshairSize * 0.3);
            ctx.beginPath();
            ctx.moveTo(mx - arm, my); ctx.lineTo(mx - gap, my);
            ctx.moveTo(mx + gap, my); ctx.lineTo(mx + arm, my);
            ctx.moveTo(mx, my - arm); ctx.lineTo(mx, my - gap);
            ctx.moveTo(mx, my + gap); ctx.lineTo(mx, my + arm);
            ctx.stroke();
        } else if (style === "x") {
            // Diagonal X crosshair
            const arm = crosshairSize * 0.75;
            const gap = Math.max(1, crosshairSize * 0.28);
            ctx.beginPath();
            ctx.moveTo(mx - arm, my - arm); ctx.lineTo(mx - gap, my - gap);
            ctx.moveTo(mx + gap, my + gap); ctx.lineTo(mx + arm, my + arm);
            ctx.moveTo(mx + arm, my - arm); ctx.lineTo(mx + gap, my - gap);
            ctx.moveTo(mx - gap, my + gap); ctx.lineTo(mx - arm, my + arm);
            ctx.stroke();
        } else {
            // Default "cross" — thin with center gap
            const arm = crosshairSize;
            const gap = Math.max(1, crosshairSize * 0.4);
            ctx.beginPath();
            ctx.moveTo(mx - arm, my); ctx.lineTo(mx - gap, my);
            ctx.moveTo(mx + gap, my); ctx.lineTo(mx + arm, my);
            ctx.moveTo(mx, my - arm); ctx.lineTo(mx, my - gap);
            ctx.moveTo(mx, my + gap); ctx.lineTo(mx, my + arm);
            ctx.stroke();
        }
        ctx.restore();
    }

    function startCrosshair() {
        if (crosshairState.enabled) return;
        primeSharedPlayerData();
        crosshairState.enabled = true;
        createCrosshairCanvas();
        setNativeCursorHidden(true);
        startUnifiedRenderLoop();
    }

    function stopCrosshair() {
        if (!crosshairState.enabled) return;
        crosshairState.enabled = false;
        setNativeCursorHidden(false);
        destroyCrosshairCanvas();
        stopUnifiedRenderLoopIfIdle();
    }

    document.addEventListener("mousemove", (e) => {
        const dx = e.clientX - crosshairState.mouseX;
        const dy = e.clientY - crosshairState.mouseY;
        const len = Math.hypot(dx, dy);
        if (len > 0.0001) {
            autoAimState.aimDirX = dx / len;
            autoAimState.aimDirY = dy / len;
        }
        crosshairState.mouseX = e.clientX;
        crosshairState.mouseY = e.clientY;
    }, { passive: true });

    window.addEventListener("resize", resizeCrosshairCanvas);
    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;
        setTimeout(() => {
            if (shouldIgnoreCrosshairEscapeDisable()) return;
            if (document.pointerLockElement) return;
            disableCrosshairModuleFromEscape();
        }, 0);
    }, false);

    // ---------------------------------------------------------------------------
    // TRIGGER ASSIST MODULE
    // Uses shared ESP bridge data and cursor position to trigger fire when
    // player targets are within a configurable cursor radius.
    // ---------------------------------------------------------------------------
    const triggerAssistState = {
        enabled: false,
        loopId: null,
        canvas: null,
        ctx: null,
        lastFireAt: 0,
        mouseHeld: false,
        releaseTimeoutId: null,
        target: null,
        statusText: "Idle",
    };

    const autoAimState = {
        enabled: false,
        rafId: null,
        canvas: null,
        ctx: null,
        target: null,
        statusText: "Idle",
        lastAimX: 0,
        lastAimY: 0,
        aimDirX: 1,
        aimDirY: 0,
        lastTickAt: 0,
        lastTargetId: null,
        targetLockUntil: 0,
        targetVelX: 0,
        targetVelY: 0,
        lastTargetSampleAt: 0,
    };

    const autoAimInputState = {
        leftMouseDown: false,
        reroutedShotActive: false,
    };

    function getTriggerAssistConfig() {
        const defaults = {
            enabled: true,
            teamCheck: true,
            fovPx: 220,
            holdToFire: false,
            fireRateMs: 16,
            requireLOS: false,
            onlyWhenGameFocused: true,
            showTargetRing: true,
        };
        const stored = window.__zyroxTriggerAssistConfig;
        return stored && typeof stored === "object" ? { ...defaults, ...stored } : defaults;
    }

    function getAutoAimConfig() {
        const defaults = {
            enabled: true,
            teamCheck: true,
            fovDeg: 180,
            smoothing: 0,
            maxStepPx: 120,
            minStepPx: 0,
            deadzonePx: 0,
            predictionMs: 0,
            lockMs: 0,
            stickToTarget: false,
            onlyWhenGameFocused: true,
            requireMouseDown: false,
            showDebugDot: true,
        };
        const stored = window.__zyroxAutoAimConfig;
        if (stored && typeof stored === "object") {
            const merged = { ...defaults, ...stored };
            if (merged.fovDeg == null && Number.isFinite(Number(stored.fovPx))) {
                merged.fovDeg = Math.max(15, Math.min(180, Number(stored.fovPx)));
            }
            return merged;
        }
        return defaults;
    }

    function createTriggerAssistCanvas() {
        if (triggerAssistState.canvas?.parentNode) return;
        const canvas = document.createElement("canvas");
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        canvas.style.cssText = "position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:10001;pointer-events:none;user-select:none;";
        document.body.appendChild(canvas);
        triggerAssistState.canvas = canvas;
        triggerAssistState.ctx = canvas.getContext("2d");
    }

    function destroyTriggerAssistCanvas() {
        triggerAssistState.canvas?.remove();
        triggerAssistState.canvas = null;
        triggerAssistState.ctx = null;
    }

    function resizeTriggerAssistCanvas() {
        if (!triggerAssistState.canvas) return;
        triggerAssistState.canvas.width = window.innerWidth;
        triggerAssistState.canvas.height = window.innerHeight;
    }

    function createAutoAimCanvas() {
        if (autoAimState.canvas?.parentNode) return;
        const canvas = document.createElement("canvas");
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        canvas.style.cssText = "position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:10002;pointer-events:none;user-select:none;";
        document.body.appendChild(canvas);
        autoAimState.canvas = canvas;
        autoAimState.ctx = canvas.getContext("2d");
    }

    function destroyAutoAimCanvas() {
        autoAimState.canvas?.remove();
        autoAimState.canvas = null;
        autoAimState.ctx = null;
    }

    function resizeAutoAimCanvas() {
        if (!autoAimState.canvas) return;
        autoAimState.canvas.width = window.innerWidth;
        autoAimState.canvas.height = window.innerHeight;
    }

    function getGameCanvas() {
        const stores = espState.stores ?? window.stores;
        return stores?.phaser?.game?.canvas
            ?? stores?.phaser?.scene?.game?.canvas
            ?? document.querySelector("canvas");
    }

    function fireCanvasPointerEvent(type, canvas, x, y) {
        if (!canvas) return;
        const rect = canvas.getBoundingClientRect();
        const clientX = rect.left + Math.max(0, Math.min(rect.width, x));
        const clientY = rect.top + Math.max(0, Math.min(rect.height, y));
        const init = {
            bubbles: true,
            cancelable: true,
            button: 0,
            buttons: type === "pointerup" || type === "mouseup" ? 0 : 1,
            clientX,
            clientY,
            pointerId: 1,
            pointerType: "mouse",
            isPrimary: true,
        };
        canvas.dispatchEvent(new PointerEvent(type, init));
    }

    function fireCanvasMouseEvent(type, canvas, x, y, buttons = 0) {
        if (!canvas) return;
        const rect = canvas.getBoundingClientRect();
        const clientX = rect.left + Math.max(0, Math.min(rect.width, x));
        const clientY = rect.top + Math.max(0, Math.min(rect.height, y));
        canvas.dispatchEvent(new MouseEvent(type, {
            bubbles: true,
            cancelable: true,
            button: 0,
            buttons,
            clientX,
            clientY,
        }));
    }


    function syncPhaserPointer(x, y) {
        try {
            const stores = espState.stores ?? window.stores;
            const scene = stores?.phaser?.scene;
            const input = scene?.input;
            const pointer = input?.activePointer || input?.mousePointer;
            if (!pointer) return;
            const nx = Math.max(0, Math.min(window.innerWidth, Number(x) || 0));
            const ny = Math.max(0, Math.min(window.innerHeight, Number(y) || 0));
            pointer.x = nx;
            pointer.y = ny;
            pointer.position?.set?.(nx, ny);
            pointer.prevPosition?.set?.(nx, ny);
            if (typeof scene?.cameras?.main?.getWorldPoint === "function") {
                const worldPoint = scene.cameras.main.getWorldPoint(nx, ny);
                if (worldPoint) {
                    pointer.worldX = worldPoint.x;
                    pointer.worldY = worldPoint.y;
                }
            }
        } catch (_) { }
    }

    function syncAimPointer(canvas, x, y, buttons = 0) {
        syncPhaserPointer(x, y);
        fireCanvasPointerEvent("pointermove", canvas, x, y);
        fireCanvasMouseEvent("mousemove", canvas, x, y, buttons);
        const clientX = Math.max(0, Math.min(window.innerWidth, Number(x) || 0));
        const clientY = Math.max(0, Math.min(window.innerHeight, Number(y) || 0));
        const moveInit = {
            bubbles: true,
            cancelable: true,
            button: 0,
            buttons,
            clientX,
            clientY,
        };
        document.dispatchEvent(new MouseEvent("mousemove", moveInit));
        window.dispatchEvent(new MouseEvent("mousemove", moveInit));
        try {
            const pointerInit = {
                ...moveInit,
                pointerId: 1,
                pointerType: "mouse",
                isPrimary: true,
            };
            document.dispatchEvent(new PointerEvent("pointermove", pointerInit));
            window.dispatchEvent(new PointerEvent("pointermove", pointerInit));
        } catch (_) { }
    }

    function releaseFireHold() {
        if (!triggerAssistState.mouseHeld) return;
        const canvas = getGameCanvas();
        if (canvas) {
            syncAimPointer(canvas, crosshairState.mouseX, crosshairState.mouseY, 0);
            fireCanvasPointerEvent("pointerup", canvas, crosshairState.mouseX, crosshairState.mouseY);
            fireCanvasMouseEvent("mouseup", canvas, crosshairState.mouseX, crosshairState.mouseY, 0);
        }
        triggerAssistState.mouseHeld = false;
    }

    function attemptFire(hold, forceRelease = false, point = null) {
        const canvas = getGameCanvas();
        if (!canvas) return false;
        canvas.focus?.({ preventScroll: true });
        const aimX = Number(point?.x ?? crosshairState.mouseX);
        const aimY = Number(point?.y ?? crosshairState.mouseY);

        if (forceRelease) {
            releaseFireHold();
            return true;
        }

        if (hold) {
            syncAimPointer(canvas, aimX, aimY, 1);
            if (!triggerAssistState.mouseHeld) {
                fireCanvasPointerEvent("pointerdown", canvas, aimX, aimY);
                fireCanvasMouseEvent("mousedown", canvas, aimX, aimY, 1);
                triggerAssistState.mouseHeld = true;
            }
            return true;
        }

        syncAimPointer(canvas, aimX, aimY, 1);
        fireCanvasPointerEvent("pointerdown", canvas, aimX, aimY);
        fireCanvasMouseEvent("mousedown", canvas, aimX, aimY, 1);
        setTimeout(() => {
            syncAimPointer(canvas, aimX, aimY, 0);
            fireCanvasPointerEvent("pointerup", canvas, aimX, aimY);
            fireCanvasMouseEvent("mouseup", canvas, aimX, aimY, 0);
        }, 12);
        return true;
    }

    function findTriggerTarget(cfg) {
        const snapshot = getAutoAimPlayerSnapshot();
        if (!snapshot?.camera || !Array.isArray(snapshot.players)) return null;
        const mx = crosshairState.mouseX;
        const my = crosshairState.mouseY;
        const espCfg = getEspRenderConfig();
        const baseHitbox = Math.max(12, Number(espCfg.hitboxSize) || 150);
        const width = window.innerWidth;
        const height = window.innerHeight;
        const margin = 80;
        let best = null;
        for (const player of snapshot.players) {
            if (!player) continue;
            const pid = String(player.id ?? "");
            if (!pid || (snapshot.localPlayerId != null && pid === String(snapshot.localPlayerId))) continue;
            if (cfg.teamCheck && snapshot.localTeamId != null && player.teamId === snapshot.localTeamId) continue;
            const screen = projectWorldToScreen(player, snapshot.camera, width, height);
            if (!screen) continue;
            if (screen.x < -margin || screen.x > width + margin || screen.y < -margin || screen.y > height + margin) continue;
            const boxSize = Math.max(24, baseHitbox * Math.max(0.01, Number(screen.zoom) || 1));
            const half = boxSize * 0.5;
            if (mx < screen.x - half || mx > screen.x + half || my < screen.y - half || my > screen.y + half) continue;
            const dist = Math.hypot(mx - screen.x, my - screen.y);
            if (!best || dist < best.distancePx) {
                best = {
                    player,
                    screenX: screen.x,
                    screenY: screen.y,
                    distancePx: dist,
                    hitboxSizePx: boxSize,
                };
            }
        }
        return best;
    }

    function getAutoAimPlayerSnapshot() {
        const shared = window.__zyroxEspShared;
        if (shared?.ready && Array.isArray(shared.players) && shared.camera) {
            return {
                localPlayerId: shared.localPlayerId ?? null,
                localTeamId: shared.localTeamId ?? null,
                camera: shared.camera,
                players: shared.players,
            };
        }

        const stores = espState.stores ?? window.stores ?? null;
        const me = stores ? getMainCharacter(stores) : null;
        const cam = stores?.phaser?.scene?.cameras?.cameras?.[0];
        if (!me || !cam) return null;
        const mePos = getCharacterPosition(me);
        const meId = String(getCharacterId(me) ?? stores?.phaser?.mainCharacter?.id ?? "");
        const meTeam = getCharacterTeam(me);
        const fallbackPlayers = [];
        for (const { id, character } of getCharacterEntries(stores)) {
            const pos = getCharacterPosition(character);
            if (!pos) continue;
            fallbackPlayers.push({
                id: String(id ?? getCharacterId(character) ?? ""),
                name: String(getCharacterName(character, id)),
                teamId: getCharacterTeam(character),
                x: pos.x,
                y: pos.y,
            });
        }
        return {
            localPlayerId: meId || (mePos ? `${mePos.x}:${mePos.y}` : null),
            localTeamId: meTeam ?? null,
            camera: {
                midX: Number(cam?.midPoint?.x ?? 0),
                midY: Number(cam?.midPoint?.y ?? 0),
                zoom: Number(cam?.zoom ?? 1),
            },
            players: fallbackPlayers,
        };
    }

    function findAutoAimTarget(cfg) {
        const snapshot = getAutoAimPlayerSnapshot();
        if (!snapshot?.camera || !Array.isArray(snapshot.players)) return null;
        const mx = crosshairState.mouseX;
        const my = crosshairState.mouseY;
        const width = window.innerWidth;
        const height = window.innerHeight;
        const margin = 80;
        const fovDeg = Math.max(15, Math.min(180, Number(cfg.fovDeg) || 120));
        const stickyFovDeg = Math.min(180, fovDeg * 1.15);
        const aimDirX = Number(autoAimState.aimDirX) || 1;
        const aimDirY = Number(autoAimState.aimDirY) || 0;
        const angleToAimDir = (toX, toY) => {
            const len = Math.hypot(toX, toY);
            if (len <= 0.001) return 0;
            const nx = toX / len;
            const ny = toY / len;
            const dot = Math.max(-1, Math.min(1, nx * aimDirX + ny * aimDirY));
            return Math.acos(dot) * (180 / Math.PI);
        };
        const canUseSticky = cfg.stickToTarget && autoAimState.target?.player;
        const now = performance.now();
        const isWithinLockWindow = autoAimState.lastTargetId != null && now < autoAimState.targetLockUntil;
        let stickyCandidate = null;
        let best = null;

        for (const player of snapshot.players) {
            if (!player) continue;
            const pid = String(player.id ?? "");
            if (!pid || (snapshot.localPlayerId != null && pid === String(snapshot.localPlayerId))) continue;
            if (cfg.teamCheck && snapshot.localTeamId != null && player.teamId === snapshot.localTeamId) continue;
            const screen = projectWorldToScreen(player, snapshot.camera, width, height);
            if (!screen) continue;
            if (screen.x < -margin || screen.x > width + margin || screen.y < -margin || screen.y > height + margin) continue;
            const dist = Math.hypot(mx - screen.x, my - screen.y);
            const angleDelta = angleToAimDir(screen.x - mx, screen.y - my);
            const score = dist;
            if (angleDelta <= fovDeg && (!best || score < best.score)) {
                best = { player, playerId: pid, screenX: screen.x, screenY: screen.y, distancePx: dist, angleDelta, score };
            }
            if (canUseSticky && pid === String(autoAimState.target.playerId) && angleDelta <= stickyFovDeg) {
                stickyCandidate = { player, playerId: pid, screenX: screen.x, screenY: screen.y, distancePx: dist, angleDelta, score };
            } else if (isWithinLockWindow && pid === String(autoAimState.lastTargetId) && angleDelta <= stickyFovDeg) {
                stickyCandidate = { player, playerId: pid, screenX: screen.x, screenY: screen.y, distancePx: dist, angleDelta, score };
            }
        }
        return stickyCandidate || best;
    }

    function renderAutoAimOverlay(cfg) {
        const ctx = autoAimState.ctx;
        const canvas = autoAimState.canvas;
        if (!ctx || !canvas) return;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        if (!cfg.showDebugDot || !autoAimState.target) return;
        const pulse = (Math.sin(performance.now() / 140) + 1) * 0.5;
        const tx = autoAimState.target.screenX;
        const ty = autoAimState.target.screenY;
        ctx.save();
        ctx.fillStyle = `rgba(255, 255, 255, ${0.55 + pulse * 0.2})`;
        ctx.strokeStyle = `rgba(255, 92, 92, ${0.7 + pulse * 0.2})`;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.arc(tx, ty, 2.8, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.arc(tx, ty, 7 + pulse * 2.5, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
    }

    function autoAimTick() {
        if (!autoAimState.enabled) return;
        const now = performance.now();
        const dtMs = autoAimState.lastTickAt > 0 ? (now - autoAimState.lastTickAt) : (1000 / 60);
        autoAimState.lastTickAt = now;
        const dtFactor = Math.max(0.45, Math.min(2.2, dtMs / (1000 / 60)));
        const cfg = getAutoAimConfig();
        if (!cfg.enabled) {
            autoAimState.target = null;
            autoAimState.statusText = "Disabled in config";
            renderAutoAimOverlay(cfg);
            return;
        }
        if (cfg.onlyWhenGameFocused && (!document.hasFocus() || document.visibilityState !== "visible")) {
            autoAimState.target = null;
            autoAimState.statusText = "Waiting for focus";
            renderAutoAimOverlay(cfg);
            return;
        }
        if (cfg.requireMouseDown && !autoAimInputState.leftMouseDown) {
            autoAimState.target = null;
            autoAimState.statusText = "Waiting for mouse hold";
            renderAutoAimOverlay(cfg);
            return;
        }

        const prevTarget = autoAimState.target;
        const target = findAutoAimTarget(cfg);
        autoAimState.target = target;
        if (!target) {
            const hasShared = window.__zyroxEspShared?.ready;
            const hasStores = Boolean((espState.stores ?? window.stores)?.phaser?.scene);
            autoAimState.statusText = (!hasShared && !hasStores) ? "Waiting for match data" : "No target";
            renderAutoAimOverlay(cfg);
            return;
        }

        const canvas = getGameCanvas();
        const smoothingValue = Number(cfg.smoothing);
        const smoothing = Math.max(0, Math.min(1, Number.isFinite(smoothingValue) ? smoothingValue : 0.2));
        const maxStep = Math.max(2, Number(cfg.maxStepPx) || 32);
        const minStepRaw = Number(cfg.minStepPx);
        const minStepAbs = Math.max(0.05, Number.isFinite(minStepRaw) ? minStepRaw : 0.35);
        const minMoveFactor = 0.01;
        const deadzone = Math.max(0, Number(cfg.deadzonePx) || 1.8);
        const predictionMs = Math.max(0, Math.min(220, Number(cfg.predictionMs) || 70));
        const lockMs = Math.max(0, Number(cfg.lockMs) || 220);

        if (target.playerId != null) {
            if (autoAimState.lastTargetId !== String(target.playerId)) {
                autoAimState.targetVelX = 0;
                autoAimState.targetVelY = 0;
            }
            if (prevTarget && prevTarget.playerId === String(target.playerId)) {
                const sampleDelta = Math.max(1, now - (autoAimState.lastTargetSampleAt || now));
                const rawVelX = (target.screenX - prevTarget.screenX) / sampleDelta;
                const rawVelY = (target.screenY - prevTarget.screenY) / sampleDelta;
                const velBlend = 0.28;
                autoAimState.targetVelX = autoAimState.targetVelX * (1 - velBlend) + rawVelX * velBlend;
                autoAimState.targetVelY = autoAimState.targetVelY * (1 - velBlend) + rawVelY * velBlend;
            }
            autoAimState.lastTargetSampleAt = now;
            autoAimState.lastTargetId = String(target.playerId);
            autoAimState.targetLockUntil = now + lockMs;
        }

        const predictedX = target.screenX + autoAimState.targetVelX * predictionMs;
        const predictedY = target.screenY + autoAimState.targetVelY * predictionMs;
        const dx = predictedX - crosshairState.mouseX;
        const dy = predictedY - crosshairState.mouseY;
        const dist = Math.hypot(dx, dy);
        if (dist > deadzone) {
            const adaptiveSmoothing = Math.pow(smoothing, dtFactor);
            const moveFactor = Math.max(minMoveFactor, Math.min(1, 1 - adaptiveSmoothing));
            const baseStep = dist * moveFactor;
            const step = Math.min(maxStep * dtFactor, Math.max(minStepAbs, baseStep));
            const ratio = Math.min(1, step / dist);
            const nextX = crosshairState.mouseX + dx * ratio;
            const nextY = crosshairState.mouseY + dy * ratio;
            const moveX = nextX - crosshairState.mouseX;
            const moveY = nextY - crosshairState.mouseY;
            const moveLen = Math.hypot(moveX, moveY);
            if (moveLen > 0.0001) {
                autoAimState.aimDirX = moveX / moveLen;
                autoAimState.aimDirY = moveY / moveLen;
            }
            crosshairState.mouseX = nextX;
            crosshairState.mouseY = nextY;
            autoAimState.lastAimX = nextX;
            autoAimState.lastAimY = nextY;
            if (canvas) syncAimPointer(canvas, nextX, nextY, autoAimInputState.leftMouseDown ? 1 : 0);
        }
        autoAimState.statusText = `Locked: ${target.player?.name ?? "Player"}`;
        renderAutoAimOverlay(cfg);
    }

    function autoAimLoop() {
        if (!autoAimState.enabled) return;
        autoAimTick();
    }

    function startAutoAim() {
        if (autoAimState.enabled) return;
        primeSharedPlayerData();
        autoAimState.enabled = true;
        autoAimState.target = null;
        autoAimState.lastTargetId = null;
        autoAimState.targetLockUntil = 0;
        autoAimState.targetVelX = 0;
        autoAimState.targetVelY = 0;
        autoAimState.lastTickAt = 0;
        autoAimState.statusText = "Armed";
        createAutoAimCanvas();
        startUnifiedRenderLoop();
    }

    function stopAutoAim() {
        if (!autoAimState.enabled) return;
        autoAimState.enabled = false;
        autoAimState.target = null;
        autoAimState.lastTargetId = null;
        autoAimState.targetLockUntil = 0;
        autoAimState.targetVelX = 0;
        autoAimState.targetVelY = 0;
        autoAimState.statusText = "Idle";
        destroyAutoAimCanvas();
        stopUnifiedRenderLoopIfIdle();
    }

    function renderTriggerAssistOverlay(cfg) {
        const ctx = triggerAssistState.ctx;
        const canvas = triggerAssistState.canvas;
        if (!ctx || !canvas) return;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        if (!cfg.showTargetRing || !triggerAssistState.target) return;
        const pulse = (Math.sin(performance.now() / 120) + 1) * 0.5;
        const ringR = Math.max(10, Number(cfg.fovPx) || 85);
        ctx.save();
        const ringGradient = ctx.createRadialGradient(
            crosshairState.mouseX,
            crosshairState.mouseY,
            Math.max(1, ringR * 0.1),
            crosshairState.mouseX,
            crosshairState.mouseY,
            ringR
        );
        ringGradient.addColorStop(0, "rgba(255, 130, 130, 0.12)");
        ringGradient.addColorStop(1, "rgba(255, 40, 40, 0.02)");
        ctx.fillStyle = ringGradient;
        ctx.beginPath();
        ctx.arc(crosshairState.mouseX, crosshairState.mouseY, ringR, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = `rgba(255, 70, 70, ${0.7 + pulse * 0.25})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(crosshairState.mouseX, crosshairState.mouseY, ringR, 0, Math.PI * 2);
        ctx.stroke();

        ctx.setLineDash([5, 5]);
        ctx.strokeStyle = `rgba(255, 225, 120, ${0.55 + pulse * 0.35})`;
        ctx.beginPath();
        ctx.moveTo(crosshairState.mouseX, crosshairState.mouseY);
        ctx.lineTo(triggerAssistState.target.screenX, triggerAssistState.target.screenY);
        ctx.stroke();

        ctx.setLineDash([]);
        ctx.strokeStyle = `rgba(255, 255, 120, ${0.8 + pulse * 0.2})`;
        ctx.beginPath();
        ctx.arc(triggerAssistState.target.screenX, triggerAssistState.target.screenY, 10 + pulse * 2.5, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
    }

    function triggerAssistTick() {
        if (!triggerAssistState.enabled) return;
        const cfg = getTriggerAssistConfig();
        if (!cfg.enabled) {
            triggerAssistState.statusText = "Disabled in config";
            triggerAssistState.target = null;
            releaseFireHold();
            renderTriggerAssistOverlay(cfg);
            return;
        }
        if (cfg.onlyWhenGameFocused && (!document.hasFocus() || document.visibilityState !== "visible")) {
            triggerAssistState.statusText = "Waiting for focus";
            triggerAssistState.target = null;
            releaseFireHold();
            renderTriggerAssistOverlay(cfg);
            return;
        }

        const target = findTriggerTarget(cfg);
        triggerAssistState.target = target;
        if (!target) {
            const hasShared = window.__zyroxEspShared?.ready;
            const hasStores = Boolean((espState.stores ?? window.stores)?.phaser?.scene);
            triggerAssistState.statusText = (!hasShared && !hasStores) ? "Waiting for match data" : "No target";
            releaseFireHold();
            renderTriggerAssistOverlay(cfg);
            return;
        }

        triggerAssistState.statusText = `Inside Hitbox: ${target.player?.name ?? "Player"}`;
        const now = Date.now();
        const minDelay = Math.max(16, Number(cfg.fireRateMs) || 45);
        if (cfg.holdToFire) {
            attemptFire(true, false, null);
        } else if (now - triggerAssistState.lastFireAt >= minDelay && attemptFire(false, false, null)) {
            triggerAssistState.lastFireAt = now;
        }

        if (triggerAssistState.releaseTimeoutId != null) clearTimeout(triggerAssistState.releaseTimeoutId);
        triggerAssistState.releaseTimeoutId = setTimeout(() => {
            if (!document.hasFocus() || document.visibilityState !== "visible") releaseFireHold();
        }, Math.max(160, minDelay * 2));

        renderTriggerAssistOverlay(cfg);
    }

    function startTriggerAssist() {
        if (triggerAssistState.enabled) return;
        primeSharedPlayerData();
        triggerAssistState.enabled = true;
        createTriggerAssistCanvas();
        triggerAssistState.statusText = "Armed";
        startUnifiedRenderLoop();
    }

    function stopTriggerAssist() {
        if (!triggerAssistState.enabled) return;
        triggerAssistState.enabled = false;
        if (triggerAssistState.releaseTimeoutId != null) {
            clearTimeout(triggerAssistState.releaseTimeoutId);
            triggerAssistState.releaseTimeoutId = null;
        }
        releaseFireHold();
        triggerAssistState.target = null;
        triggerAssistState.statusText = "Idle";
        destroyTriggerAssistCanvas();
        stopUnifiedRenderLoopIfIdle();
    }

    function runTimedModule(key, fn) {
        const start = performance.now();
        fn();
        const elapsed = performance.now() - start;
        renderDiagnostics.moduleMs[key] = renderDiagnostics.moduleMs[key] * 0.85 + elapsed * 0.15;
    }

    function unifiedRenderTick(now) {
        if (!unifiedRenderState.running) return;
        if (renderDiagnostics.lastFrameAt > 0) {
            const dt = now - renderDiagnostics.lastFrameAt;
            if (dt > 25) renderDiagnostics.droppedFrames += 1;
        }
        renderDiagnostics.lastFrameAt = now;
        renderDiagnostics.frameCount += 1;

        if (espState.enabled) runTimedModule("esp", renderEspTick);
        if (crosshairState.enabled) runTimedModule("crosshair", renderCrosshairFrame);
        if (autoAimState.enabled) runTimedModule("autoAim", autoAimTick);
        if (triggerAssistState.enabled) runTimedModule("triggerAssist", triggerAssistTick);
        if (cameraZoomState.enabled) runTimedModule("cameraZoom", applyCameraZoomTick);

        unifiedRenderState.rafId = requestAnimationFrame(unifiedRenderTick);
    }

    function startUnifiedRenderLoop() {
        if (unifiedRenderState.running) return;
        unifiedRenderState.running = true;
        unifiedRenderState.rafId = requestAnimationFrame(unifiedRenderTick);
    }

    function stopUnifiedRenderLoopIfIdle() {
        if (espState.enabled || crosshairState.enabled || autoAimState.enabled || triggerAssistState.enabled || cameraZoomState.enabled) return;
        unifiedRenderState.running = false;
        if (unifiedRenderState.rafId != null) {
            cancelAnimationFrame(unifiedRenderState.rafId);
            unifiedRenderState.rafId = null;
        }
    }

    window.addEventListener("blur", () => {
        autoAimInputState.leftMouseDown = false;
        autoAimInputState.reroutedShotActive = false;
        autoAimState.target = null;
        releaseFireHold();
    });
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState !== "visible") {
            autoAimInputState.leftMouseDown = false;
            autoAimInputState.reroutedShotActive = false;
            autoAimState.target = null;
            releaseFireHold();
        }
    });
    window.addEventListener("resize", resizeTriggerAssistCanvas);
    window.addEventListener("resize", resizeAutoAimCanvas);
    function isEventInsideUi(target) {
        const el = target instanceof Element ? target : null;
        return Boolean(el?.closest(".zyrox-root, .zyrox-config-backdrop, .zyrox-settings, .zyrox-config"));
    }

    function shouldRerouteManualShot(event) {
        if (!event || event.button !== 0) return false;
        if (isEventInsideUi(event.target)) return false;
        if (!autoAimState.enabled || !autoAimState.target) return false;
        if (triggerAssistState.enabled) return false;
        const cfg = getAutoAimConfig();
        if (!cfg.enabled) return false;
        if (cfg.onlyWhenGameFocused && (!document.hasFocus() || document.visibilityState !== "visible")) return false;
        return true;
    }

    window.addEventListener("mousedown", (event) => {
        if (!shouldRerouteManualShot(event)) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        autoAimInputState.leftMouseDown = true;
        autoAimInputState.reroutedShotActive = true;
        attemptFire(false, false, { x: crosshairState.mouseX, y: crosshairState.mouseY });
    }, true);

    window.addEventListener("mouseup", (event) => {
        if (event.button !== 0 || isEventInsideUi(event.target)) return;
        if (!autoAimInputState.reroutedShotActive) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        autoAimInputState.leftMouseDown = false;
        autoAimInputState.reroutedShotActive = false;
    }, true);

    window.addEventListener("mousedown", (event) => {
        if (event.button === 0 && !isEventInsideUi(event.target)) autoAimInputState.leftMouseDown = true;
    }, { passive: true });
    window.addEventListener("mouseup", (event) => {
        if (event.button === 0) {
            autoAimInputState.leftMouseDown = false;
            autoAimInputState.reroutedShotActive = false;
        }
    }, { passive: true });

    const answerPopupState = {
        enabled: false,
        container: null,
        timeoutId: null,
        lastAnswer: "",
        lastShownAt: 0,
        lastRenderedAnswer: "",
    };
    const drawItAnswerRevealState = {
        enabled: false,
        selectorMode: "auto",
        lastAnswer: "",
        syncIntervalId: null,
    };

    function getAnswerRevealConfig() {
        if (typeof state !== "undefined" && state?.moduleConfig instanceof Map) {
            const saved = state.moduleConfig.get("Answer Reveal");
            if (saved && typeof saved === "object") {
                return {
                    selectorMode: saved.selectorMode === "strict" ? "strict" : "auto",
                };
            }
        }
        return { selectorMode: "auto" };
    }

    function findDrawItMaskedTermElement(selectorMode = "auto") {
        const strictSelectors = [
            ".sc-iKrZTU.cVnVFI span",
            ".sc-iKrZTU.cVnVFI",
            "[data-qa='term-mask']",
            "[data-testid='term-mask']",
            "[class*='term'][class*='mask']",
        ];
        const autoSelectors = [
            ...strictSelectors,
            "[class*='word'][class*='mask']",
            "[class*='draw'][class*='term']",
            ".hSIGsV .cVnVFI span",
            ".hSIGsV .cVnVFI",
            "[data-qa*='term']",
            "[data-testid*='term']",
        ];
        const selectors = selectorMode === "strict" ? strictSelectors : autoSelectors;
        for (const selector of selectors) {
            const hit = document.querySelector(selector);
            if (hit && typeof hit.textContent === "string") return hit;
        }
        return null;
    }

    function applyDrawItAnswerReveal(answerText) {
        if (!drawItAnswerRevealState.enabled) return;
        const answer = String(answerText || "").trim();
        if (!answer) return;
        drawItAnswerRevealState.lastAnswer = answer;
        forceDrawItAnswerReveal();
    }

    function forceDrawItAnswerReveal() {
        if (!drawItAnswerRevealState.enabled) return;
        const answer = String(drawItAnswerRevealState.lastAnswer || "").trim();
        if (!answer) return;
        const target = findDrawItMaskedTermElement(drawItAnswerRevealState.selectorMode);
        if (!target) return;
        if (!target.dataset.zyroxOriginalMask) {
            target.dataset.zyroxOriginalMask = String(target.textContent || "");
        }
        if (target.textContent !== answer) target.textContent = answer;
    }

    function restoreDrawItAnswerMask() {
        const target = findDrawItMaskedTermElement(drawItAnswerRevealState.selectorMode);
        if (!target) return;
        const originalMask = target.dataset.zyroxOriginalMask;
        if (typeof originalMask === "string" && originalMask.length) {
            target.textContent = originalMask;
            delete target.dataset.zyroxOriginalMask;
        }
    }

    function startDrawItAnswerReveal() {
        const cfg = getAnswerRevealConfig();
        drawItAnswerRevealState.selectorMode = cfg.selectorMode;
        drawItAnswerRevealState.enabled = true;
        if (!drawItAnswerRevealState.syncIntervalId) {
            drawItAnswerRevealState.syncIntervalId = setInterval(forceDrawItAnswerReveal, 50);
        }
    }

    function stopDrawItAnswerReveal() {
        drawItAnswerRevealState.enabled = false;
        drawItAnswerRevealState.lastAnswer = "";
        if (drawItAnswerRevealState.syncIntervalId) {
            clearInterval(drawItAnswerRevealState.syncIntervalId);
            drawItAnswerRevealState.syncIntervalId = null;
        }
        restoreDrawItAnswerMask();
    }

    const ANSWER_POPUP_PRESETS = {
        default: { accent: "#ff4a4a", textColor: "#ffffff", durationMs: 2600, panelBg: "rgba(8, 10, 14, 0.92)", headerStart: "rgba(255, 74, 74, 0.30)", headerEnd: "rgba(45, 12, 12, 0.95)" },
        green: { accent: "#2dff75", textColor: "#e8fff1", durationMs: 2400, panelBg: "rgba(7, 20, 12, 0.92)", headerStart: "rgba(45, 255, 117, 0.30)", headerEnd: "rgba(15, 47, 27, 0.95)" },
        ice: { accent: "#6cd8ff", textColor: "#eaf7ff", durationMs: 2400, panelBg: "rgba(8, 17, 24, 0.92)", headerStart: "rgba(108, 216, 255, 0.30)", headerEnd: "rgba(19, 48, 66, 0.95)" },
        grayscale: { accent: "#d4d4d4", textColor: "#f1f1f1", durationMs: 2600, panelBg: "rgba(18, 18, 18, 0.92)", headerStart: "rgba(143, 143, 143, 0.30)", headerEnd: "rgba(29, 29, 29, 0.95)" },
    };

    function normalizePopupPresetName(name) {
        const key = String(name || "default").toLowerCase();
        return Object.prototype.hasOwnProperty.call(ANSWER_POPUP_PRESETS, key) ? key : "default";
    }

    function getGlobalPresetName() {
        const name = typeof state !== "undefined" ? state?.globalPreset : "default";
        return normalizePopupPresetName(name || "default");
    }

    function getEffectivePopupPresetName(selectedPresetName) {
        const selected = normalizePopupPresetName(selectedPresetName);
        return selected === "default" ? getGlobalPresetName() : selected;
    }

    function applyAnswerPopupPreset(cfg, presetName) {
        const name = normalizePopupPresetName(presetName);
        const preset = ANSWER_POPUP_PRESETS[getEffectivePopupPresetName(name)] || ANSWER_POPUP_PRESETS.default;
        cfg.preset = name;
        cfg.accent = preset.accent;
        cfg.textColor = preset.textColor;
        cfg.durationMs = preset.durationMs;
    }

    function getAnswerPopupConfig() {
        const defaults = {
            preset: "default",
            text: "answer",
            durationMs: 2600,
            accent: "#ff4a4a",
            textColor: "#ffffff",
        };
        let cfg = defaults;
        if (typeof state !== "undefined" && state?.moduleConfig instanceof Map) {
            const saved = state.moduleConfig.get("Answer Popup");
            if (saved && typeof saved === "object") cfg = { ...defaults, ...saved };
        }
        const selectedPreset = normalizePopupPresetName(cfg.preset || "default");
        const effectivePresetName = getEffectivePopupPresetName(selectedPreset);
        const preset = ANSWER_POPUP_PRESETS[effectivePresetName] || ANSWER_POPUP_PRESETS.default;
        const usePresetOnly = selectedPreset === "default";
        return {
            globalPreset: getGlobalPresetName(),
            preset: selectedPreset,
            effectivePreset: effectivePresetName,
            text: String(cfg.text ?? defaults.text),
            durationMs: Math.max(
                400,
                Number(usePresetOnly ? preset.durationMs : (cfg.durationMs ?? preset.durationMs ?? defaults.durationMs)) || defaults.durationMs,
            ),
            accent: String(usePresetOnly ? preset.accent : (cfg.accent ?? preset.accent ?? defaults.accent)),
            textColor: String(usePresetOnly ? preset.textColor : (cfg.textColor ?? preset.textColor ?? defaults.textColor)),
            panelBg: String(preset.panelBg ?? ANSWER_POPUP_PRESETS.default.panelBg),
            headerStart: String(preset.headerStart ?? ANSWER_POPUP_PRESETS.default.headerStart),
            headerEnd: String(preset.headerEnd ?? ANSWER_POPUP_PRESETS.default.headerEnd),
            headerText: String(usePresetOnly ? preset.textColor : (cfg.textColor ?? preset.textColor ?? defaults.textColor)),
        };
    }

    function ensureAnswerPopupContainer() {
        if (answerPopupState.container?.isConnected) return answerPopupState.container;
        const popup = document.createElement("div");
        popup.className = "zyrox-answer-popup";
        popup.style.cssText = [
            "position:fixed",
            "left:50%",
            "top:92px",
            "transform:translate(-50%, -18px)",
            "min-width:260px",
            "max-width:min(86vw,640px)",
            "padding:0",
            "border-radius:12px",
            "font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif",
            "z-index:2147483647",
            "opacity:0",
            "pointer-events:none",
            "transition:opacity .18s ease, transform .18s ease",
            "box-shadow:0 14px 34px rgba(0,0,0,.45)",
            "border:1px solid rgba(255,255,255,.14)",
            "display:none",
            "overflow:hidden",
            "white-space:normal",
            "overflow-wrap:anywhere",
        ].join(";");
        document.documentElement.appendChild(popup);
        answerPopupState.container = popup;
        return popup;
    }

    function showAnswerPopup(answerText) {
        if (!answerPopupState.enabled) return;
        const answer = String(answerText || "").trim();
        if (!answer) return;
        const now = Date.now();
        if (answer === answerPopupState.lastAnswer && now - answerPopupState.lastShownAt < 700) return;
        answerPopupState.lastAnswer = answer;
        answerPopupState.lastShownAt = now;
        answerPopupState.lastRenderedAnswer = answer;

        const popup = ensureAnswerPopupContainer();
        const cfg = getAnswerPopupConfig();
        popup.style.background = cfg.panelBg;
        popup.style.color = cfg.textColor;
        popup.style.borderLeft = `4px solid ${cfg.accent}`;
        popup.style.border = "1px solid rgba(255,255,255,.14)";
        popup.style.boxShadow = "0 14px 34px rgba(0,0,0,.45)";
        const label = cfg.text.trim();
        popup.innerHTML = `
      <div style="padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.1);background:linear-gradient(90deg, ${cfg.headerStart}, ${cfg.headerEnd});color:${cfg.headerText};font-size:13px;font-weight:700;text-transform:capitalize;">${label || "answer"}</div>
      <div style="padding:10px 12px;font-size:16px;font-weight:700;line-height:1.25;"><span style="color:${cfg.accent};">${answer}</span></div>
    `;

        popup.style.display = "block";
        popup.style.opacity = "1";
        popup.style.transform = "translate(-50%, 0)";
        if (answerPopupState.timeoutId) clearTimeout(answerPopupState.timeoutId);
        answerPopupState.timeoutId = setTimeout(() => {
            popup.style.opacity = "0";
            popup.style.transform = "translate(-50%, -18px)";
            setTimeout(() => {
                if (popup.style.opacity === "0") popup.style.display = "none";
            }, 180);
        }, cfg.durationMs);
    }

    function refreshVisibleAnswerPopup() {
        if (!answerPopupState.container) return;
        if (answerPopupState.container.style.display === "none") return;
        const answer = String(answerPopupState.lastRenderedAnswer || "").trim();
        if (!answer) return;
        const cfg = getAnswerPopupConfig();
        answerPopupState.container.style.background = cfg.panelBg;
        answerPopupState.container.style.color = cfg.textColor;
        answerPopupState.container.style.borderLeft = `4px solid ${cfg.accent}`;
        const label = cfg.text.trim();
        answerPopupState.container.innerHTML = `
      <div style="padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.1);background:linear-gradient(90deg, ${cfg.headerStart}, ${cfg.headerEnd});color:${cfg.headerText};font-size:13px;font-weight:700;text-transform:capitalize;">${label || "answer"}</div>
      <div style="padding:10px 12px;font-size:16px;font-weight:700;line-height:1.25;"><span style="color:${cfg.accent};">${answer}</span></div>
    `;
    }

    function startAnswerPopup() {
        answerPopupState.enabled = true;
    }

    function stopAnswerPopup() {
        answerPopupState.enabled = false;
        if (answerPopupState.timeoutId) {
            clearTimeout(answerPopupState.timeoutId);
            answerPopupState.timeoutId = null;
        }
        if (answerPopupState.container) {
            answerPopupState.container.style.opacity = "0";
            answerPopupState.container.style.display = "none";
        }
        answerPopupState.lastRenderedAnswer = "";
    }

    const UPGRADE_HUD_LABELS = {
        moneyPerQuestion: "Money Per Question",
        streakBonus: "Streak Bonus",
        multiplier: "Multiplier",
        insurance: "Insurance",
    };
    const UPGRADE_HUD_COSTS_BY_TARGET_LEVEL = {
        moneyPerQuestion: { 2: 10, 3: 100, 4: 1000, 5: 10000, 6: 75000, 7: 300000, 8: 1000000, 9: 10000000, 10: 100000000 },
        streakBonus: { 2: 20, 3: 200, 4: 2000, 5: 20000, 6: 200000, 7: 2000000, 8: 20000000, 9: 200000000, 10: 2000000000 },
        multiplier: { 2: 50, 3: 300, 4: 2000, 5: 12000, 6: 85000, 7: 700000, 8: 6500000, 9: 65000000, 10: 1000000000 },
        insurance: { 2: 10, 3: 250, 4: 1000, 5: 25000, 6: 100000, 7: 1000000, 8: 5000000, 9: 25000000, 10: 500000000 },
    };
    const upgradeHudState = {
        enabled: false,
        container: null,
        config: {
            displayTitle: true,
            showLvlPrefix: false,
            showUpgradeButton: true,
            hudSize: 100,
        },
        levels: {
            moneyPerQuestion: 1,
            streakBonus: 1,
            multiplier: 1,
            insurance: 1,
        },
        balance: 0,
    };
    const UPGRADE_HUD_LOG_PREFIX = "[Upgrade HUD]";
    const AUTO_UPGRADE_LOG_PREFIX = "[Auto Upgrade]";
    const AUTO_UPGRADE_TIE_BREAK_ORDER = ["moneyPerQuestion", "streakBonus", "multiplier", "insurance"];
    const autoUpgradeState = {
        enabled: false,
        intervalId: null,
        toggles: {
            multiplier: true,
            moneyPerQuestion: true,
            streakBonus: true,
            insurance: true,
        },
        order: [...AUTO_UPGRADE_TIE_BREAK_ORDER],
    };
    const UPGRADE_HUD_TOP_OFFSET_PX = 39;

    function upgradeHudLog(message, extra) {
        if (extra === undefined) console.log(`${UPGRADE_HUD_LOG_PREFIX} ${message}`);
        else console.log(`${UPGRADE_HUD_LOG_PREFIX} ${message}`, extra);
    }

    function isRememberHudPositionEnabled(value, fallback = true) {
        if (value === undefined || value === null) return fallback;
        if (value === false || value === "false" || value === 0 || value === "0") return false;
        return true;
    }

    function parseBooleanSetting(value, fallback = false) {
        if (value === undefined || value === null) return fallback;
        if (value === true || value === "true" || value === 1 || value === "1") return true;
        if (value === false || value === "false" || value === 0 || value === "0") return false;
        return Boolean(value);
    }

    function normalizeHudPosition(pos, fallback = null) {
        const normalizePoint = (value) => {
            if (!value || typeof value !== "object") return null;
            const rawX = value.x ?? value.left ?? value.hudPositionX;
            const rawY = value.y ?? value.top ?? value.hudPositionY;
            const x = Number.parseFloat(rawX);
            const y = Number.parseFloat(rawY);
            if (Number.isFinite(x) && Number.isFinite(y)) return { x, y };
            return null;
        };
        return normalizePoint(pos) || normalizePoint(fallback) || null;
    }


    function readModuleConfigFromStorage(moduleName) {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return null;
            const saved = JSON.parse(raw);
            const moduleConfig = Array.isArray(saved?.moduleConfig) ? saved.moduleConfig : [];
            for (const entry of moduleConfig) {
                if (!Array.isArray(entry) || entry.length < 2) continue;
                if (entry[0] !== moduleName) continue;
                const cfg = entry[1];
                if (cfg && typeof cfg === "object") return { ...cfg };
                break;
            }
        } catch (_) { }
        return null;
    }

    function readHudPositionFromStorage(moduleName, fallback = null) {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return normalizeHudPosition(null, fallback);
            const saved = JSON.parse(raw);
            const moduleConfig = Array.isArray(saved?.moduleConfig) ? saved.moduleConfig : [];
            for (const entry of moduleConfig) {
                if (!Array.isArray(entry) || entry.length < 2) continue;
                if (entry[0] !== moduleName) continue;
                const cfg = entry[1] && typeof entry[1] === "object" ? entry[1] : null;
                if (!cfg) break;
                const legacy = { x: cfg.hudPositionX, y: cfg.hudPositionY, left: cfg.left, top: cfg.top };
                return normalizeHudPosition(cfg.hudPosition, legacy || fallback);
            }
        } catch (_) { }
        return normalizeHudPosition(null, fallback);
    }

    function readHudPosition(moduleName, fallback = null) {
        const cfg = getHudModuleConfigObject(moduleName, {});
        const legacy = cfg && typeof cfg === "object"
            ? { x: cfg.hudPositionX, y: cfg.hudPositionY, left: cfg.left, top: cfg.top }
            : null;
        const fromCfg = normalizeHudPosition(cfg?.hudPosition, legacy || null);
        if (fromCfg) return fromCfg;
        return readHudPositionFromStorage(moduleName, fallback);
    }

    function persistHudPositionToStorage(moduleName, hudPosition) {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return;
            const saved = JSON.parse(raw);
            const moduleConfig = Array.isArray(saved?.moduleConfig) ? saved.moduleConfig.slice() : [];
            let found = false;
            for (let i = 0; i < moduleConfig.length; i += 1) {
                const entry = moduleConfig[i];
                if (!Array.isArray(entry) || entry.length < 2) continue;
                if (entry[0] !== moduleName) continue;
                const cfg = entry[1] && typeof entry[1] === "object" ? { ...entry[1] } : {};
                cfg.hudPosition = { x: Math.round(Number(hudPosition.x) || 0), y: Math.round(Number(hudPosition.y) || 0) };
                moduleConfig[i] = [entry[0], cfg];
                found = true;
                break;
            }
            if (!found) moduleConfig.push([moduleName, { keybind: null, hudPosition: { x: Math.round(Number(hudPosition.x) || 0), y: Math.round(Number(hudPosition.y) || 0) } }]);
            saved.moduleConfig = moduleConfig;
            localStorage.setItem(STORAGE_KEY, JSON.stringify(saved));
            console.log("[HUD Position] Forced localStorage sync", { moduleName, hudPosition: { x: Math.round(Number(hudPosition.x) || 0), y: Math.round(Number(hudPosition.y) || 0) } });
        } catch (_) { }
    }

    function writeHudPosition(moduleName, pos) {
        const normalized = normalizeHudPosition(pos, null);
        if (!normalized) return null;
        const cfg = getHudModuleConfigObject(moduleName, {});
        if (!cfg || typeof cfg !== "object") return null;
        cfg.hudPosition = { x: Math.round(normalized.x), y: Math.round(normalized.y) };
        console.log("[HUD Position] Stored", { moduleName, hudPosition: { ...cfg.hudPosition } });
        persistHudPositionToStorage(moduleName, cfg.hudPosition);
        markHudFallbackConfigDirty(moduleName);
        if (typeof saveSettings === "function") saveSettings();
        return { ...cfg.hudPosition };
    }

    function readHudPositionFromElement(el) {
        if (!el) return null;
        const left = Number.parseFloat(el.style.left || "");
        const top = Number.parseFloat(el.style.top || "");
        if (!Number.isFinite(left) || !Number.isFinite(top)) return null;
        return { x: left, y: top };
    }

    function applyHudPosition(el, pos, clamp = true) {
        if (!el || !pos || !Number.isFinite(pos.x) || !Number.isFinite(pos.y)) return null;
        const rect = el.getBoundingClientRect();
        const width = Math.max(1, rect.width || el.offsetWidth || 1);
        const height = Math.max(1, rect.height || el.offsetHeight || 1);
        const maxX = Math.max(0, window.innerWidth - width);
        const maxY = Math.max(0, window.innerHeight - height);
        const next = clamp
            ? { x: Math.max(0, Math.min(maxX, Number(pos.x) || 0)), y: Math.max(0, Math.min(maxY, Number(pos.y) || 0)) }
            : { x: Number(pos.x) || 0, y: Number(pos.y) || 0 };
        el.style.removeProperty("right");
        el.style.removeProperty("bottom");
        el.style.setProperty("left", `${next.x}px`);
        el.style.setProperty("top", `${next.y}px`);
        return next;
    }



    function markHudFallbackConfigDirty(moduleName) {
        const dirtyKey = "__zyroxHudFallbackConfigDirty";
        if (!window[dirtyKey] || typeof window[dirtyKey] !== "object") window[dirtyKey] = {};
        window[dirtyKey][moduleName] = true;
    }

    function getHudModuleConfigObject(moduleName, defaults = {}) {
        const cacheKey = "__zyroxHudFallbackConfig";
        const dirtyKey = "__zyroxHudFallbackConfigDirty";
        if (!window[cacheKey] || typeof window[cacheKey] !== "object") window[cacheKey] = {};
        if (!window[dirtyKey] || typeof window[dirtyKey] !== "object") window[dirtyKey] = {};

        try {
            if (typeof moduleCfg === "function") {
                const cfg = moduleCfg(moduleName);
                if (cfg && typeof cfg === "object") {
                    const fallbackCfg = window[cacheKey][moduleName];
                    const fallbackDirty = window[dirtyKey][moduleName] === true;
                    if (fallbackCfg && typeof fallbackCfg === "object") {
                        if (fallbackDirty) {
                            for (const [key, value] of Object.entries(fallbackCfg)) cfg[key] = value;
                        }
                        delete window[cacheKey][moduleName];
                        delete window[dirtyKey][moduleName];
                    }
                    return cfg;
                }
            }
        } catch (_) { }

        if (!window[cacheKey][moduleName] || typeof window[cacheKey][moduleName] !== "object") {
            window[cacheKey][moduleName] = { ...defaults, ...(readModuleConfigFromStorage(moduleName) || {}) };
        }
        return window[cacheKey][moduleName];
    }

    function normalizeUpgradeHudConfigFromRaw(rawCfg = {}) {
        const defaults = { displayTitle: true, showLvlPrefix: false, showUpgradeButton: true, hudSize: 100, hudPosition: null };
        return {
            displayTitle: parseBooleanSetting(rawCfg.displayTitle, defaults.displayTitle),
            showLvlPrefix: parseBooleanSetting(rawCfg.showLvlPrefix, defaults.showLvlPrefix),
            showUpgradeButton: parseBooleanSetting(rawCfg.showUpgradeButton, defaults.showUpgradeButton),
            hudSize: Number.isFinite(Number(rawCfg.hudSize)) ? Math.max(60, Math.min(180, Number(rawCfg.hudSize))) : defaults.hudSize,
            hudPosition: normalizeHudPosition(rawCfg.hudPosition, defaults.hudPosition),
        };
    }

    function normalizeBuildingHudConfigFromRaw(rawCfg = {}) {
        const defaults = { displayTitle: true, hudSize: 100, hudPosition: null };
        return {
            displayTitle: parseBooleanSetting(rawCfg.displayTitle, defaults.displayTitle),
            hudSize: Number.isFinite(Number(rawCfg.hudSize)) ? Math.max(60, Math.min(180, Number(rawCfg.hudSize))) : defaults.hudSize,
            hudPosition: normalizeHudPosition(rawCfg.hudPosition, defaults.hudPosition),
        };
    }

    function readUpgradeHudConfig() {
        const cfg = getHudModuleConfigObject("Upgrade HUD", { displayTitle: true, showLvlPrefix: false, showUpgradeButton: true, hudSize: 100, hudPosition: null });
        const normalized = normalizeUpgradeHudConfigFromRaw(cfg);
        Object.assign(upgradeHudState.config, normalized);
        return { ...normalized };
    }

    function writeUpgradeHudConfigPatch(patch = {}) {
        const cfg = getHudModuleConfigObject("Upgrade HUD", { displayTitle: true, showLvlPrefix: false, showUpgradeButton: true, hudSize: 100, hudPosition: null });
        if (!cfg || typeof cfg !== "object") return readUpgradeHudConfig();
        Object.assign(cfg, patch);
        markHudFallbackConfigDirty("Building HUD");
        markHudFallbackConfigDirty("Upgrade HUD");
        const normalized = normalizeUpgradeHudConfigFromRaw(cfg);
        Object.assign(cfg, normalized);
        Object.assign(upgradeHudState.config, normalized);
        if (typeof saveSettings === "function") saveSettings();
        return { ...normalized };
    }

    function readBuildingHudConfig() {
        const cfg = getHudModuleConfigObject("Building HUD", { displayTitle: true, hudSize: 100, hudPosition: null });
        const normalized = normalizeBuildingHudConfigFromRaw(cfg);
        Object.assign(lavaBuildingHudState.config, normalized);
        return { ...normalized };
    }

    function writeBuildingHudConfigPatch(patch = {}) {
        const cfg = getHudModuleConfigObject("Building HUD", { displayTitle: true, hudSize: 100, hudPosition: null });
        if (!cfg || typeof cfg !== "object") return readBuildingHudConfig();
        Object.assign(cfg, patch);
        const normalized = normalizeBuildingHudConfigFromRaw(cfg);
        Object.assign(cfg, normalized);
        Object.assign(lavaBuildingHudState.config, normalized);
        if (typeof saveSettings === "function") saveSettings();
        return { ...normalized };
    }

    function ensureUpgradeHudContainer() {
        if (upgradeHudState.container?.isConnected) return upgradeHudState.container;
        if (!document.getElementById("zyrox-upgrade-hud-style")) {
            const style = document.createElement("style");
            style.id = "zyrox-upgrade-hud-style";
            style.textContent = `
        .zyrox-upgrade-hud-button:hover:not(:disabled) {
          outline: 2px solid rgba(255,255,255,.95);
          outline-offset: 1px;
        }
      `;
            document.documentElement.appendChild(style);
        }
        const hud = document.createElement("div");
        hud.className = "zyrox-upgrade-hud";
        hud.style.cssText = [
            "position:fixed",
            `top:${UPGRADE_HUD_TOP_OFFSET_PX}px`,
            "right:14px",
            "min-width:220px",
            "max-width:min(38vw,360px)",
            "padding:10px 12px",
            "border-radius:10px",
            "background:rgba(8,12,17,.88)",
            "border:1px solid rgba(255,255,255,.14)",
            "box-shadow:0 12px 30px rgba(0,0,0,.42)",
            "z-index:2147483646",
            "color:#fff",
            "font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif",
            "display:none",
            "pointer-events:auto",
            "cursor:grab",
            "user-select:none",
        ].join(";");
        let dragState = null;
        const clampToViewport = (nextX, nextY) => {
            const rect = hud.getBoundingClientRect();
            const maxX = Math.max(0, window.innerWidth - rect.width);
            const maxY = Math.max(0, window.innerHeight - rect.height);
            return {
                x: Math.max(0, Math.min(maxX, Number(nextX) || 0)),
                y: Math.max(0, Math.min(maxY, Number(nextY) || 0)),
            };
        };
        const handleMouseMove = (event) => {
            if (!dragState) return;
            const nextX = event.clientX - dragState.offsetX;
            const nextY = event.clientY - dragState.offsetY;
            const clamped = clampToViewport(nextX, nextY);
            applyHudPosition(hud, clamped, false);
            writeUpgradeHudConfigPatch({ hudPosition: { x: Math.round(clamped.x), y: Math.round(clamped.y) } });
        };
        const handleDragEnd = () => {
            if (!dragState) return;
            const rect = hud.getBoundingClientRect();
            const clamped = clampToViewport(rect.left, rect.top);
            writeHudPosition("Upgrade HUD", { x: Math.round(clamped.x), y: Math.round(clamped.y) });
            if (typeof saveSettings === "function") saveSettings();
            dragState = null;
            hud.style.cursor = "grab";
            document.removeEventListener("mousemove", handleMouseMove);
            document.removeEventListener("mouseup", handleDragEnd);
            window.removeEventListener("blur", handleDragEnd);
            document.removeEventListener("mouseleave", handleDragEnd);
            document.removeEventListener("visibilitychange", handleVisibilityChange);
        };
        const handleVisibilityChange = () => {
            if (document.visibilityState === "hidden") handleDragEnd();
        };
        hud.addEventListener("mousedown", (event) => {
            if (event.button !== 0) return;
            const rect = hud.getBoundingClientRect();
            dragState = {
                offsetX: event.clientX - rect.left,
                offsetY: event.clientY - rect.top,
            };
            hud.style.cursor = "grabbing";
            document.addEventListener("mousemove", handleMouseMove);
            document.addEventListener("mouseup", handleDragEnd);
            window.addEventListener("blur", handleDragEnd);
            document.addEventListener("mouseleave", handleDragEnd);
            document.addEventListener("visibilitychange", handleVisibilityChange);
            event.preventDefault();
        });
        const savedPos = readHudPosition("Upgrade HUD", null);
        if (savedPos) {
            const applied = applyHudPosition(hud, savedPos, true);
            upgradeHudLog("Restored HUD position", { moduleName: "Upgrade HUD", saved: savedPos, applied });
        } else {
            upgradeHudLog("No saved HUD position found; using default anchor", { moduleName: "Upgrade HUD", rawCfg: (() => { try { return moduleCfg("Upgrade HUD"); } catch (_) { return null; } })(), storagePos: readHudPositionFromStorage("Upgrade HUD", null) });
        }
        document.documentElement.appendChild(hud);
        upgradeHudState.container = hud;
        return hud;
    }

    function getUpgradeHudConfig() {
        return readUpgradeHudConfig();
    }

    function getLavaBuildingHudConfig() {
        return readBuildingHudConfig();
    }

    function applyUpgradeHudPosition(hud, cfg, moduleName = "Upgrade HUD") {
        const storedPos = readHudPosition(moduleName, null);
        const sourcePos = normalizeHudPosition(storedPos, cfg?.hudPosition);
        if (sourcePos) {
            const applied = applyHudPosition(hud, sourcePos, true);
            upgradeHudLog(`Position source=${storedPos ? "moduleCfg" : "runtime"}`, { moduleName, requested: sourcePos, applied });
            return applied;
        }
        upgradeHudLog("Position source=default-anchor", { moduleName });
        hud.style.removeProperty("top");
        hud.style.removeProperty("right");
        hud.style.removeProperty("bottom");
        hud.style.removeProperty("left");
        hud.style.setProperty("top", `${UPGRADE_HUD_TOP_OFFSET_PX}px`);
        hud.style.setProperty("right", "14px");
        const width = Math.max(1, hud.offsetWidth || hud.getBoundingClientRect().width || 220);
        const anchored = { x: Math.max(0, window.innerWidth - width - 14), y: UPGRADE_HUD_TOP_OFFSET_PX };
        const applied = applyHudPosition(hud, anchored, true);
        return applied;
    }

    function renderUpgradeHud(configOverride = null) {
        const hud = ensureUpgradeHudContainer();
        const cfg = { ...getUpgradeHudConfig(), ...(configOverride && typeof configOverride === "object" ? configOverride : {}) };
        if (!normalizeHudPosition(cfg.hudPosition, null)) {
            const livePos = readHudPositionFromElement(hud);
            if (livePos) {
                writeHudPosition("Upgrade HUD", livePos);
                cfg.hudPosition = livePos;
            }
        }
        const sizeScale = Math.max(0.6, Math.min(1.8, Number(cfg.hudSize || 100) / 100));
        hud.style.minWidth = `${Math.round(220 * sizeScale)}px`;
        hud.style.padding = `${Math.round(10 * sizeScale)}px ${Math.round(12 * sizeScale)}px`;
        hud.style.borderRadius = `${Math.round(10 * sizeScale)}px`;
        const appliedPos = applyUpgradeHudPosition(hud, cfg, "Upgrade HUD");
        if (appliedPos) writeHudPosition("Upgrade HUD", appliedPos);
        const rows = Object.keys(UPGRADE_HUD_LABELS)
            .map((key) => {
                const label = UPGRADE_HUD_LABELS[key];
                const level = Number(upgradeHudState.levels[key]) || 1;
                const levelText = cfg.showLvlPrefix ? `Lvl ${level}` : `${level}`;
                const nextLevel = level + 1;
                const nextCost = UPGRADE_HUD_COSTS_BY_TARGET_LEVEL[key]?.[nextLevel];
                const canAfford = Number.isFinite(nextCost) && Number(upgradeHudState.balance) >= nextCost;
                const isMaxed = !Number.isFinite(nextCost);
                const costText = isMaxed ? "MAX" : `$${Number(nextCost).toLocaleString()}`;
                const buttonBg = isMaxed ? "rgba(255,255,255,.09)" : (canAfford ? "rgba(46,204,113,.35)" : "rgba(255,255,255,.09)");
                const buttonBorder = isMaxed ? "rgba(255,255,255,.24)" : (canAfford ? "rgba(46,204,113,.82)" : "rgba(255,255,255,.24)");
                const buttonColor = isMaxed ? "rgba(255,255,255,.55)" : "#fff";
                const buttonHtml = cfg.showUpgradeButton
                    ? `<button class="zyrox-upgrade-hud-button" data-upgrade-key="${key}" data-upgrade-cost="${isMaxed ? "" : nextCost}" ${isMaxed ? "disabled" : ""} style="appearance:none;border:1px solid ${buttonBorder};background:${buttonBg};color:${buttonColor};border-radius:${Math.max(5, Math.round(6 * sizeScale))}px;padding:${Math.max(2, Math.round(3 * sizeScale))}px ${Math.max(6, Math.round(8 * sizeScale))}px;font-size:${Math.max(10, Math.round(11 * sizeScale))}px;font-weight:700;line-height:1;cursor:${isMaxed ? "default" : "pointer"};min-width:${Math.max(62, Math.round(72 * sizeScale))}px;text-align:center;">${costText}</button>`
                    : "";
                return `<div style="display:grid;grid-template-columns:minmax(0,1fr) ${Math.max(28, Math.round(34 * sizeScale))}px auto;align-items:center;column-gap:${Math.round(10 * sizeScale)}px;padding:${Math.max(1, Math.round(2 * sizeScale))}px 0;font-size:${Math.max(11, Math.round(13 * sizeScale))}px;"><span style="opacity:.88;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${label}</span><b style="text-align:right;">${levelText}</b>${buttonHtml || '<span></span>'}</div>`;
            })
            .join("");
        const titleRow = cfg.displayTitle
            ? `<div style="font-size:${Math.max(10, Math.round(12 * sizeScale))}px;text-transform:uppercase;letter-spacing:.05em;opacity:.72;margin-bottom:${Math.max(4, Math.round(6 * sizeScale))}px;">Upgrades</div>`
            : "";
        hud.innerHTML = `${titleRow}${rows}`;
        if (cfg.showUpgradeButton) {
            const buttons = hud.querySelectorAll(".zyrox-upgrade-hud-button");
            for (const button of buttons) {
                button.addEventListener("mousedown", (event) => {
                    event.stopPropagation();
                });
                button.addEventListener("click", (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const key = String(button.getAttribute("data-upgrade-key") || "");
                    if (!key || !UPGRADE_HUD_LABELS[key]) return;
                    const cost = Number(button.getAttribute("data-upgrade-cost"));
                    if (Number.isFinite(cost) && Number(upgradeHudState.balance) < cost) return;
                    const currentLevel = Number(upgradeHudState.levels[key]) || 1;
                    const nextLevel = currentLevel + 1;
                    const sent = sendUpgradePurchase(key, nextLevel);
                    if (sent) upgradeHudLog("Sent UPGRADE_PURCHASED", { key, nextLevel });
                });
            }
        }
        hud.style.display = upgradeHudState.enabled ? "block" : "none";
    }

    function hardRefreshUpgradeHud(configOverride = null) {
        if (upgradeHudState.container?.isConnected) upgradeHudState.container.remove();
        upgradeHudState.container = null;
        renderUpgradeHud(configOverride);
    }

    function extractUpgradeLevelsFromStateUpdate(stateUpdate) {
        const tryReadLevels = (entry) => {
            if (!entry || typeof entry !== "object") return null;
            if (entry.type === "UPGRADE_LEVELS" && entry.value && typeof entry.value === "object") return entry.value;
            return null;
        };

        const direct = tryReadLevels(stateUpdate);
        if (direct) return direct;

        if (Array.isArray(stateUpdate)) {
            for (const entry of stateUpdate) {
                const levels = tryReadLevels(entry);
                if (levels) return levels;
            }
        }

        if (stateUpdate && typeof stateUpdate === "object") {
            const nested = tryReadLevels(stateUpdate.data);
            if (nested) return nested;
            const payloadNested = tryReadLevels(stateUpdate.payload?.data);
            if (payloadNested) return payloadNested;
        }

        return null;
    }

    function extractBalanceFromStateUpdate(stateUpdate) {
        const tryReadBalance = (entry) => {
            if (!entry || typeof entry !== "object") return null;
            if (entry.type !== "BALANCE") return null;
            const parsed = Number(entry.value);
            return Number.isFinite(parsed) ? parsed : null;
        };

        const direct = tryReadBalance(stateUpdate);
        if (direct != null) return direct;

        if (Array.isArray(stateUpdate)) {
            for (const entry of stateUpdate) {
                const balance = extractBalanceFromStateUpdate(entry);
                if (balance != null) return balance;
            }
        }

        if (stateUpdate && typeof stateUpdate === "object") {
            const nested = tryReadBalance(stateUpdate.data);
            if (nested != null) return nested;
            const payloadNested = tryReadBalance(stateUpdate.payload?.data);
            if (payloadNested != null) return payloadNested;
        }

        return null;
    }

    function updateUpgradeHudLevels(nextLevels) {
        if (!nextLevels || typeof nextLevels !== "object") return;
        const before = { ...upgradeHudState.levels };
        for (const key of Object.keys(UPGRADE_HUD_LABELS)) {
            if (typeof nextLevels[key] === "undefined") continue;
            const n = Number(nextLevels[key]);
            upgradeHudState.levels[key] = Number.isFinite(n) ? n : 1;
        }
        upgradeHudLog("Applied UPGRADE_LEVELS update", { before, incoming: nextLevels, after: { ...upgradeHudState.levels } });
        if (upgradeHudState.enabled) renderUpgradeHud();
    }

    function updateUpgradeHudBalance(nextBalance) {
        const parsed = Number(nextBalance);
        if (!Number.isFinite(parsed)) return;
        upgradeHudState.balance = parsed;
        if (upgradeHudState.enabled) renderUpgradeHud();
    }

    function startUpgradeHud() {
        upgradeHudState.enabled = true;
        upgradeHudLog("Enabled");
        renderUpgradeHud();
    }

    function stopUpgradeHud() {
        upgradeHudState.enabled = false;
        upgradeHudLog("Disabled");
        if (upgradeHudState.container) {
            upgradeHudState.container.style.display = "none";
        }
    }


    function autoUpgradeLog(message, extra) {
        if (extra === undefined) console.log(`${AUTO_UPGRADE_LOG_PREFIX} ${message}`);
        else console.log(`${AUTO_UPGRADE_LOG_PREFIX} ${message}`, extra);
    }


    function getAutoUpgradeConfig() {
        const defaults = { ...autoUpgradeState.toggles };
        const defaultOrder = [...AUTO_UPGRADE_TIE_BREAK_ORDER];
        const parseToggle = (value, fallback) => {
            if (value === undefined || value === null) return fallback;
            if (typeof value === "boolean") return value;
            if (typeof value === "number") return value === 1;
            if (typeof value === "string") {
                const normalized = value.trim().toLowerCase();
                if (["false", "0", "off", "no", "disabled"].includes(normalized)) return false;
                if (["true", "1", "on", "yes", "enabled"].includes(normalized)) return true;
            }
            return false;
        };
        try {
            const cfg = getModuleConfigSafe("Auto Upgrade");
            const resolved = {
                multiplier: parseToggle(cfg.multiplier, defaults.multiplier),
                moneyPerQuestion: parseToggle(cfg.moneyPerQuestion, defaults.moneyPerQuestion),
                streakBonus: parseToggle(cfg.streakBonus, defaults.streakBonus),
                insurance: parseToggle(cfg.insurance, defaults.insurance),
            };
            const configuredOrder = Array.isArray(cfg.order) ? cfg.order.filter((key) => defaultOrder.includes(key)) : [];
            const normalizedOrder = [...configuredOrder];
            for (const key of defaultOrder) if (!normalizedOrder.includes(key)) normalizedOrder.push(key);
            autoUpgradeState.toggles = { ...resolved };
            autoUpgradeState.order = normalizedOrder;
            return resolved;
        } catch (_) {
            autoUpgradeState.order = [...defaultOrder];
            return { ...defaults };
        }
    }

    function getAutoUpgradeSelection() {
        const balance = Number(upgradeHudState.balance);
        if (!Number.isFinite(balance) || balance <= 0) return null;

        const cfg = getAutoUpgradeConfig();
        const candidates = [];
        for (const key of Object.keys(UPGRADE_HUD_LABELS)) {
            if (cfg[key] !== true) continue;
            const level = Number(upgradeHudState.levels[key]) || 1;
            const nextLevel = level + 1;
            const cost = Number(UPGRADE_HUD_COSTS_BY_TARGET_LEVEL[key]?.[nextLevel]);
            if (!Number.isFinite(cost) || cost > balance) continue;
            candidates.push({ key, level, nextLevel, cost });
        }
        if (!candidates.length) return null;

        candidates.sort((a, b) => {
            if (a.cost !== b.cost) return a.cost - b.cost;
            return autoUpgradeState.order.indexOf(a.key) - autoUpgradeState.order.indexOf(b.key);
        });

        return candidates[0] || null;
    }

    function sendUpgradePacketForCategory(key, nextLevel) {
        const payload = { upgradeName: UPGRADE_HUD_LABELS[key], level: nextLevel };
        const roomId = socketManager?.blueboatRoomId;
        const socket = socketManager?.socket;
        if (socket && roomId) {
            const encoded = blueboat.encode("UPGRADE_PURCHASED", payload, roomId);
            socket.send(encoded);
            return true;
        }
        socketManager.sendMessage("UPGRADE_PURCHASED", payload);
        return true;
    }

    function sendMultiplierUpgrade(nextLevel) {
        if (autoUpgradeState.toggles.multiplier !== true) return false;
        return sendUpgradePacketForCategory("multiplier", nextLevel);
    }

    function sendMoneyPerQuestionUpgrade(nextLevel) {
        if (autoUpgradeState.toggles.moneyPerQuestion !== true) return false;
        return sendUpgradePacketForCategory("moneyPerQuestion", nextLevel);
    }

    function sendStreakBonusUpgrade(nextLevel) {
        if (autoUpgradeState.toggles.streakBonus !== true) return false;
        return sendUpgradePacketForCategory("streakBonus", nextLevel);
    }

    function sendInsuranceUpgrade(nextLevel) {
        if (autoUpgradeState.toggles.insurance !== true) return false;
        return sendUpgradePacketForCategory("insurance", nextLevel);
    }

    function sendUpgradePurchase(key, nextLevel, source = "manual") {
        if (!key || !UPGRADE_HUD_LABELS[key]) return false;
        if (source === "auto") {
            if (autoUpgradeState.toggles[key] !== true) {
                autoUpgradeLog("Skipped disabled upgrade category", { key, nextLevel });
                return false;
            }
        }

        if (key === "multiplier") return sendMultiplierUpgrade(nextLevel);
        if (key === "moneyPerQuestion") return sendMoneyPerQuestionUpgrade(nextLevel);
        if (key === "streakBonus") return sendStreakBonusUpgrade(nextLevel);
        if (key === "insurance") return sendInsuranceUpgrade(nextLevel);
        return false;
    }

    function tickAutoUpgrade() {
        if (!autoUpgradeState.enabled) return;
        getAutoUpgradeConfig();
        const selection = getAutoUpgradeSelection();
        if (!selection) return;
        const sent = sendUpgradePurchase(selection.key, selection.nextLevel, "auto");
        if (sent) autoUpgradeLog("Purchased cheapest available upgrade", selection);
    }

    function startAutoUpgrade() {
        autoUpgradeState.enabled = true;
        getAutoUpgradeConfig();
        if (autoUpgradeState.intervalId) clearInterval(autoUpgradeState.intervalId);
        autoUpgradeState.intervalId = setInterval(tickAutoUpgrade, 150);
        autoUpgradeLog("Enabled");
    }

    function stopAutoUpgrade() {
        autoUpgradeState.enabled = false;
        if (autoUpgradeState.intervalId) {
            clearInterval(autoUpgradeState.intervalId);
            autoUpgradeState.intervalId = null;
        }
        autoUpgradeLog("Disabled");
    }


    const LAVA_BUILDING_OPTIONS = [
        { label: "Plank", cost: 5, packetType: "plank" },
        { label: "Brick", cost: 50, packetType: "brick" },
        { label: "Staircase", cost: 500, packetType: "wall" },
        { label: "House", cost: 5000, packetType: "house" },
        { label: "Shopping Mall", cost: 50000, packetType: "shoppingMall" },
        { label: "Skyscraper", cost: 500000, packetType: "skyscaper" },
        { label: "Mountain", cost: 5000000, packetType: "mountain" },
        { label: "Space Elevator", cost: 50000000, packetType: "spaceElevator" },
    ];

    function sendLavaBuildingPurchase(packetType) {
        if (!packetType) return false;
        const payload = { type: packetType };
        const roomId = socketManager?.blueboatRoomId;
        const socket = socketManager?.socket;
        if (socket && roomId) {
            const encoded = blueboat.encode("LAVA_PURCHASE_PIECE", payload, roomId);
            socket.send(encoded);
            return true;
        }
        socketManager.sendMessage("LAVA_PURCHASE_PIECE", payload);
        return true;
    }

    function ensureLavaBuildingHudContainer() {
        if (lavaBuildingHudState.container?.isConnected) return lavaBuildingHudState.container;
        const hud = document.createElement("div");
        hud.className = "zyrox-upgrade-hud";
        hud.style.cssText = "position:fixed;top:39px;right:14px;min-width:220px;max-width:min(38vw,360px);padding:10px 12px;border-radius:10px;background:rgba(8,12,17,.88);border:1px solid rgba(255,255,255,.14);box-shadow:0 12px 30px rgba(0,0,0,.42);z-index:2147483646;color:#fff;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;display:none;pointer-events:auto;cursor:grab;user-select:none;";
        let dragState = null;
        const clampToViewport = (nextX, nextY) => {
            const rect = hud.getBoundingClientRect();
            const maxX = Math.max(0, window.innerWidth - rect.width);
            const maxY = Math.max(0, window.innerHeight - rect.height);
            return { x: Math.max(0, Math.min(maxX, Number(nextX) || 0)), y: Math.max(0, Math.min(maxY, Number(nextY) || 0)) };
        };
        const handleMouseMove = (event) => {
            if (!dragState) return;
            const clamped = clampToViewport(event.clientX - dragState.offsetX, event.clientY - dragState.offsetY);
            applyHudPosition(hud, clamped, false);
            writeBuildingHudConfigPatch({ hudPosition: { x: Math.round(clamped.x), y: Math.round(clamped.y) } });
        };
        const handleDragEnd = () => {
            if (!dragState) return;
            const rect = hud.getBoundingClientRect();
            const clamped = clampToViewport(rect.left, rect.top);
            writeHudPosition("Building HUD", { x: Math.round(clamped.x), y: Math.round(clamped.y) });
            if (typeof saveSettings === "function") saveSettings();
            dragState = null;
            hud.style.cursor = "grab";
            document.removeEventListener("mousemove", handleMouseMove);
            document.removeEventListener("mouseup", handleDragEnd);
            window.removeEventListener("blur", handleDragEnd);
            document.removeEventListener("mouseleave", handleDragEnd);
            document.removeEventListener("visibilitychange", handleVisibilityChange);
        };
        const handleVisibilityChange = () => {
            if (document.visibilityState === "hidden") handleDragEnd();
        };
        hud.addEventListener("mousedown", (event) => {
            if (event.button !== 0) return;
            const rect = hud.getBoundingClientRect();
            dragState = { offsetX: event.clientX - rect.left, offsetY: event.clientY - rect.top };
            hud.style.cursor = "grabbing";
            document.addEventListener("mousemove", handleMouseMove);
            document.addEventListener("mouseup", handleDragEnd);
            window.addEventListener("blur", handleDragEnd);
            document.addEventListener("mouseleave", handleDragEnd);
            document.addEventListener("visibilitychange", handleVisibilityChange);
            event.preventDefault();
        });
        const savedPos = readHudPosition("Building HUD", null);
        if (savedPos) {
            const applied = applyHudPosition(hud, savedPos, true);
            upgradeHudLog("Restored HUD position", { moduleName: "Building HUD", saved: savedPos, applied });
        } else {
            upgradeHudLog("No saved HUD position found; using default anchor", { moduleName: "Building HUD", rawCfg: (() => { try { return moduleCfg("Building HUD"); } catch (_) { return null; } })(), storagePos: readHudPositionFromStorage("Building HUD", null) });
        }
        document.documentElement.appendChild(hud);
        lavaBuildingHudState.container = hud;
        return hud;
    }

    function renderLavaBuildingHud(configOverride = null) {
        const hud = ensureLavaBuildingHudContainer();
        const cfg = { ...getLavaBuildingHudConfig(), ...(configOverride && typeof configOverride === "object" ? configOverride : {}) };
        if (!normalizeHudPosition(cfg.hudPosition, null)) {
            const livePos = readHudPositionFromElement(hud);
            if (livePos) {
                writeHudPosition("Building HUD", livePos);
                cfg.hudPosition = livePos;
            }
        }
        const sizeScale = Math.max(0.6, Math.min(1.8, Number(cfg.hudSize || 100) / 100));
        hud.style.minWidth = `${Math.round(220 * sizeScale)}px`;
        hud.style.padding = `${Math.round(10 * sizeScale)}px ${Math.round(12 * sizeScale)}px`;
        hud.style.borderRadius = `${Math.round(10 * sizeScale)}px`;
        const appliedPos = applyUpgradeHudPosition(hud, cfg, "Building HUD");
        if (appliedPos) writeHudPosition("Building HUD", appliedPos);

        const titleRow = cfg.displayTitle !== false
            ? `<div style="font-size:${Math.max(10, Math.round(12 * sizeScale))}px;text-transform:uppercase;letter-spacing:.05em;opacity:.72;margin-bottom:${Math.max(4, Math.round(6 * sizeScale))}px;">Buildings</div>`
            : "";
        const rows = LAVA_BUILDING_OPTIONS.map((build) => {
            const canAfford = lavaBuildingHudState.balance >= build.cost;
            return `<div style="display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;column-gap:${Math.round(10 * sizeScale)}px;padding:${Math.max(1, Math.round(2 * sizeScale))}px 0;font-size:${Math.max(11, Math.round(13 * sizeScale))}px;"><span style="opacity:.88;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${build.label}</span><button class="zyrox-upgrade-hud-button" data-lava-type="${build.packetType}" ${canAfford ? "" : "disabled"} style="appearance:none;border:1px solid ${canAfford ? "rgba(46,204,113,.82)" : "rgba(255,255,255,.24)"};background:${canAfford ? "rgba(46,204,113,.35)" : "rgba(255,255,255,.09)"};color:#fff;border-radius:${Math.max(5, Math.round(6 * sizeScale))}px;padding:${Math.max(2, Math.round(3 * sizeScale))}px ${Math.max(6, Math.round(8 * sizeScale))}px;font-size:${Math.max(10, Math.round(11 * sizeScale))}px;font-weight:700;line-height:1;cursor:${canAfford ? "pointer" : "default"};min-width:${Math.max(62, Math.round(72 * sizeScale))}px;text-align:center;">$${build.cost.toLocaleString()}</button></div>`;
        }).join("");
        hud.innerHTML = `${titleRow}${rows}`;
        for (const button of hud.querySelectorAll("[data-lava-type]")) {
            button.addEventListener("click", (event) => {
                event.preventDefault();
                event.stopPropagation();
                const packetType = String(button.getAttribute("data-lava-type") || "");
                sendLavaBuildingPurchase(packetType);
            });
        }
        hud.style.display = lavaBuildingHudState.enabled ? "block" : "none";
    }

    function hardRefreshLavaBuildingHud(configOverride = null) {
        if (lavaBuildingHudState.container?.isConnected) lavaBuildingHudState.container.remove();
        lavaBuildingHudState.container = null;
        renderLavaBuildingHud(configOverride);
    }

    function startLavaBuildingHud() {
        lavaBuildingHudState.enabled = true;
        const hud = ensureLavaBuildingHudContainer();
        hud.style.display = "block";
        renderLavaBuildingHud();
    }

    function stopLavaBuildingHud() {
        lavaBuildingHudState.enabled = false;
        if (lavaBuildingHudState.container) lavaBuildingHudState.container.style.display = "none";
    }

    const HIDE_POPUPS_MODULE_NAME = "Hide pop-ups";
    const HIDE_POPUPS_LOG_PREFIX = "[ZyroxHidePopups]";
    const HIDE_POPUPS_TOAST_SELECTOR = ".Toastify__toast";
    const HIDE_POPUPS_TOAST_CLOSE_SELECTOR = ".Toastify__close-button";
    const HIDE_POPUPS_ENERGY_POPUP_SELECTOR = ".maxAll.flex.hc";
    const HIDE_POPUPS_ENERGY_RESOURCE_PATH = "/assets/map/inventory/resources/";
    const HIDE_POPUPS_ENERGY_RESOURCE_IMAGE_SELECTOR = `img[src*='${HIDE_POPUPS_ENERGY_RESOURCE_PATH}']`;

    const hidePopupsState = {
        enabled: false,
        observer: null,
        hiddenBuildingPopups: 0,
        hiddenEnergyPopups: 0,
    };

    function hidePopupsLog(...args) {
        console.log(HIDE_POPUPS_LOG_PREFIX, ...args);
    }

    function getHidePopupsConfig() {
        const cfg = typeof moduleCfg === "function" ? moduleCfg(HIDE_POPUPS_MODULE_NAME) : {};
        return {
            hideEnergyPopups: cfg?.hideEnergyPopups !== false,
            hideBuildingPopups: cfg?.hideBuildingPopups !== false,
        };
    }

    function isHidePopupsElement(node) {
        return node instanceof Element;
    }

    function isHidePopupsEnergyResourceImage(node) {
        if (!isHidePopupsElement(node) || node.tagName !== "IMG") return false;

        const src = node.getAttribute("src") || node.src || node.currentSrc || "";
        return src.includes(HIDE_POPUPS_ENERGY_RESOURCE_PATH);
    }

    function isHidePopupsEnergyPopup(node) {
        return isHidePopupsElement(node)
            && node.matches(HIDE_POPUPS_ENERGY_POPUP_SELECTOR)
            && Boolean(node.querySelector(HIDE_POPUPS_ENERGY_RESOURCE_IMAGE_SELECTOR));
    }

    function findHidePopupsEnergyPopup(node) {
        if (!isHidePopupsElement(node)) return null;
        if (isHidePopupsEnergyPopup(node)) return node;

        const popup = isHidePopupsEnergyResourceImage(node)
            ? node.closest(HIDE_POPUPS_ENERGY_POPUP_SELECTOR)
            : node.querySelector(HIDE_POPUPS_ENERGY_RESOURCE_IMAGE_SELECTOR)?.closest(HIDE_POPUPS_ENERGY_POPUP_SELECTOR);
        return isHidePopupsEnergyPopup(popup) ? popup : null;
    }

    function hideBuildingPopup(toast) {
        const cfg = getHidePopupsConfig();
        if (!hidePopupsState.enabled
            || !cfg.hideBuildingPopups
            || !isHidePopupsElement(toast)
            || toast.dataset.zyroxPopupHidden === "building") return false;

        toast.dataset.zyroxPopupHidden = "building";
        toast.style.display = "none";
        toast.querySelector(HIDE_POPUPS_TOAST_CLOSE_SELECTOR)?.click();
        hidePopupsState.hiddenBuildingPopups += 1;
        hidePopupsLog("Hid building popup", toast);
        return true;
    }

    function hideEnergyPopup(popup) {
        const cfg = getHidePopupsConfig();
        if (!hidePopupsState.enabled
            || !cfg.hideEnergyPopups
            || !isHidePopupsEnergyPopup(popup)
            || popup.dataset.zyroxPopupHidden === "energy") return false;

        popup.dataset.zyroxPopupHidden = "energy";
        popup.style.display = "none";
        hidePopupsState.hiddenEnergyPopups += 1;
        hidePopupsLog("Hid energy/resource popup", popup);
        return true;
    }

    function scanHidePopupNode(node) {
        if (!isHidePopupsElement(node)) return;

        if (node.matches(HIDE_POPUPS_TOAST_SELECTOR)) hideBuildingPopup(node);
        const energyPopup = findHidePopupsEnergyPopup(node);
        if (energyPopup) hideEnergyPopup(energyPopup);

        node.querySelectorAll?.(HIDE_POPUPS_TOAST_SELECTOR).forEach(hideBuildingPopup);
        node.querySelectorAll?.(HIDE_POPUPS_ENERGY_POPUP_SELECTOR).forEach((candidate) => {
            if (isHidePopupsEnergyPopup(candidate)) hideEnergyPopup(candidate);
        });
        node.querySelectorAll?.(HIDE_POPUPS_ENERGY_RESOURCE_IMAGE_SELECTOR).forEach((image) => {
            const popup = findHidePopupsEnergyPopup(image);
            if (popup) hideEnergyPopup(popup);
        });
    }

    function scanHidePopupsDocument() {
        scanHidePopupNode(document.documentElement);
    }

    function observeHidePopups() {
        if (hidePopupsState.observer || !document.documentElement) return;

        hidePopupsState.observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                if (mutation.type === "attributes") scanHidePopupNode(mutation.target);
                for (const node of mutation.addedNodes) scanHidePopupNode(node);
            }
        });

        hidePopupsState.observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "src"], childList: true, subtree: true });
    }

    function syncHidePopups() {
        if (hidePopupsState.enabled) scanHidePopupsDocument();
    }

    function startHidePopups() {
        hidePopupsState.enabled = true;
        observeHidePopups();
        scanHidePopupsDocument();
        hidePopupsLog("Enabled");
    }

    function stopHidePopups() {
        hidePopupsState.enabled = false;
        hidePopupsLog("Disabled");
    }

    window.__zyroxHidePopups = {
        enable: startHidePopups,
        disable: stopHidePopups,
        rescan: scanHidePopupsDocument,
        sync: syncHidePopups,
        status() {
            return {
                enabled: hidePopupsState.enabled,
                observer: Boolean(hidePopupsState.observer),
                ...getHidePopupsConfig(),
                hiddenBuildingPopups: hidePopupsState.hiddenBuildingPopups,
                hiddenEnergyPopups: hidePopupsState.hiddenEnergyPopups,
            };
        },
    };

    const ANIMATION_SKIP_MODULE_NAME = "Animation skip (UI)";
    const LEGACY_ANIMATION_SKIP_MODULE_NAME = "Animation Skip";
    const ANIMATION_SKIP_STYLE_ID = "zyrox-animation-skip-style";
    let originalElementAnimate = null;
    let animationSkipRouteWatcher = null;

    function isLikelyInActiveMatch() {
        return !!document.querySelector("canvas");
    }

    function shouldPauseAnimationSkipForJoinMenu() {
        const onJoinRoute = String(location?.pathname || "").startsWith("/join");
        return onJoinRoute && !isLikelyInActiveMatch();
    }

    function applyAnimationSkipState(enabled) {
        if (!enabled) {
            const styleEl = document.getElementById(ANIMATION_SKIP_STYLE_ID);
            if (styleEl) styleEl.remove();
            if (originalElementAnimate && typeof Element !== "undefined") {
                Element.prototype.animate = originalElementAnimate;
                originalElementAnimate = null;
            }
            return;
        }

        let styleEl = document.getElementById(ANIMATION_SKIP_STYLE_ID);
        if (!styleEl) {
            styleEl = document.createElement("style");
            styleEl.id = ANIMATION_SKIP_STYLE_ID;
            document.documentElement.appendChild(styleEl);
        }
        styleEl.textContent = `
      *, *::before, *::after {
        transition: none !important;
        transition-duration: 0ms !important;
        transition-delay: 0ms !important;
        animation: none !important;
        animation-duration: 0ms !important;
        animation-delay: 0ms !important;
        animation-iteration-count: 1 !important;
        scroll-behavior: auto !important;
      }
    `;

        if (!originalElementAnimate && typeof Element !== "undefined" && typeof Element.prototype?.animate === "function") {
            originalElementAnimate = Element.prototype.animate;
            Element.prototype.animate = function patchedAnimate(keyframes, options) {
                const normalized = typeof options === "number" ? { duration: options } : { ...(options || {}) };
                normalized.duration = 0;
                normalized.delay = 0;
                normalized.endDelay = 0;
                normalized.iterations = 1;
                const animation = originalElementAnimate.call(this, keyframes, normalized);
                try { animation.finish(); } catch (_) { }
                return animation;
            };
        }
    }

    function startAnimationSkip() {
        const syncMode = () => applyAnimationSkipState(!shouldPauseAnimationSkipForJoinMenu());
        syncMode();
        if (animationSkipRouteWatcher) clearInterval(animationSkipRouteWatcher);
        animationSkipRouteWatcher = setInterval(syncMode, 400);
    }

    function stopAnimationSkip() {
        if (animationSkipRouteWatcher) {
            clearInterval(animationSkipRouteWatcher);
            animationSkipRouteWatcher = null;
        }
        applyAnimationSkipState(false);
    }

    function getModuleConfigSafe(name, fallback = {}) {
        if (typeof moduleCfg !== "function") return fallback;
        try {
            return moduleCfg(name) || fallback;
        } catch (_) {
            return fallback;
        }
    }

    const ANTI_AFK_MODULE_NAME = "Anti AFK";
    const antiAfkState = {
        intervalId: null,
        phase: 0,
    };

    function getAntiAfkConfig() {
        const cfg = getModuleConfigSafe(ANTI_AFK_MODULE_NAME);
        const pulseMs = Math.max(4000, Number(cfg.pulseMs) || 12000);
        return { pulseMs };
    }

    function dispatchAntiAfkPulse() {
        const phase = antiAfkState.phase++ % 4;
        if (phase === 0) {
            window.dispatchEvent(new MouseEvent("mousemove", { clientX: 6, clientY: 6, bubbles: true }));
            return;
        }
        if (phase === 1) {
            window.dispatchEvent(new MouseEvent("mousemove", { clientX: 10, clientY: 10, bubbles: true }));
            return;
        }
        if (phase === 2) {
            window.dispatchEvent(new KeyboardEvent("keydown", { key: "Shift", code: "ShiftLeft", bubbles: true }));
            return;
        }
        document.dispatchEvent(new Event("visibilitychange", { bubbles: false }));
    }

    function startAntiAfk() {
        if (antiAfkState.intervalId) clearInterval(antiAfkState.intervalId);
        const { pulseMs } = getAntiAfkConfig();
        dispatchAntiAfkPulse();
        antiAfkState.intervalId = setInterval(() => {
            dispatchAntiAfkPulse();
        }, pulseMs);
    }

    function stopAntiAfk() {
        if (antiAfkState.intervalId) {
            clearInterval(antiAfkState.intervalId);
            antiAfkState.intervalId = null;
        }
    }

    const ABILITY_HUD_MODULE_NAME = "Ability HUD";
    const ABILITY_HUD_LOG = "[AbilityHUD]";
    const ABILITY_HUD_INTERNAL_OPACITY = 0.95;
    const ABILITY_HUD_INTERNAL_Z_INDEX = 2147483646;
    const ABILITY_HUD_DRAG_MARGIN = 10;
    const ABILITY_HUD_CONFIG_DEFAULTS = {
        // Switch between detailed card rows and compact icon tiles.
        abilityHudDisplayMode: "icons",
        // Scales the entire HUD UI (container + content).
        abilityHudScale: 0.9,
        // Gap spacing between icon tiles (pixels).
        abilityHudGap: 5,
        // Toggle price labels in both default + icon modes.
        abilityHudShowPrices: true,
        // Icon tile size (pixels).
        abilityHudIconSize: 96,
    };
    const abilityHudState = {
        enabled: false,
        container: null,
        body: null,
        abilities: new Map(),
        currentBalance: 0,
        roomId: null,
        isDragging: false,
        dragOffsetX: 0,
        dragOffsetY: 0,
        position: { x: null, y: null },
        renderTimerId: null,
        wired: false,
        listeners: null,
        packetLogCount: 0,
        purchasedAbilities: new Set(),
        usedAbilities: new Set(),
        pendingTargetAbility: null,
        pendingTargetRequestedAt: 0,
        selfPlayerId: null,
        config: { ...ABILITY_HUD_CONFIG_DEFAULTS },
        iconTiles: [],
    };

    function calculateAbilityCost(ability, playerState = {}) {
        const baseCost = Number(ability?.baseCost) || 0;
        const percentageCost = Number(ability?.percentageCost) || 0;
        const balance = Number(playerState?.balance) || 0;
        const rawCost = (percentageCost * balance) + baseCost;
        const roundedCost = Math.ceil(rawCost / 5) * 5;
        return { rawCost, roundedCost, displayCost: roundedCost };
    }

    function extractAbilitiesFromPacket(packet) {
        const containers = [
            packet?.data,
            packet?.payload?.data,
            packet?.payload,
            packet,
        ].filter(Boolean);

        for (const container of containers) {
            const direct = container?.powerups;
            if (Array.isArray(direct)) return direct;
            const fallback = container?.abilities;
            if (Array.isArray(fallback)) return fallback;
        }

        for (const container of containers) {
            if (!container || typeof container !== "object") continue;
            for (const value of Object.values(container)) {
                if (!value || typeof value !== "object") continue;
                if (Array.isArray(value?.powerups)) return value.powerups;
                if (Array.isArray(value?.abilities)) return value.abilities;
            }
        }

        return [];
    }

    function normalizeAbility(entry) {
        if (!entry || typeof entry !== "object") return null;
        const name = typeof entry.name === "string" ? entry.name.trim() : "";
        if (!name) return null;
        const displayName = typeof entry.displayName === "string" && entry.displayName.trim() ? entry.displayName.trim() : name;
        return {
            name,
            displayName,
            description: typeof entry.description === "string" ? entry.description : "",
            icon: typeof entry.icon === "string" ? entry.icon : "",
            color: {
                background: entry?.color?.background || "#2a2f3a",
                text: entry?.color?.text || "#ffffff",
            },
            baseCost: Number(entry.baseCost) || 0,
            percentageCost: Number(entry.percentageCost) || 0,
            disabled: Array.isArray(entry.disabled) ? entry.disabled.slice() : [],
        };
    }

    function requestAbilityHudRender() {
        if (!abilityHudState.enabled || !abilityHudState.container) return;
        if (abilityHudState.renderTimerId) clearTimeout(abilityHudState.renderTimerId);
        abilityHudState.renderTimerId = setTimeout(() => {
            abilityHudState.renderTimerId = null;
            renderAbilityHud();
        }, 35);
    }

    function getAbilityHudConfig() {
        const readModuleCfg = () => {
            if (typeof moduleCfg === "function") {
                try { return moduleCfg(ABILITY_HUD_MODULE_NAME); } catch (_) { }
            }
            return abilityHudState.config || ABILITY_HUD_CONFIG_DEFAULTS;
        };
        try {
            return getAbilityHudConfigFromRaw(readModuleCfg());
        } catch (_) {
            return getAbilityHudConfigFromRaw(abilityHudState.config || ABILITY_HUD_CONFIG_DEFAULTS);
        }
    }

    function getAbilityHudDefaultPosition(panelRect) {
        const inset = 18;
        const topInset = 116;
        const width = Math.max(100, panelRect?.width || 360);
        return { x: window.innerWidth - width - inset, y: topInset };
    }

    function clampAbilityHudPosition(x, y, panelRect) {
        const width = Math.max(100, panelRect?.width || 360);
        const height = Math.max(44, panelRect?.height || 120);
        const minX = ABILITY_HUD_DRAG_MARGIN;
        const minY = ABILITY_HUD_DRAG_MARGIN;
        const maxX = Math.max(minX, window.innerWidth - width - ABILITY_HUD_DRAG_MARGIN);
        const maxY = Math.max(minY, window.innerHeight - height - ABILITY_HUD_DRAG_MARGIN);
        return { x: Math.max(minX, Math.min(maxX, Number(x) || minX)), y: Math.max(minY, Math.min(maxY, Number(y) || minY)) };
    }

    function persistAbilityHudPosition() {
        try {
            const cfg = moduleCfg(ABILITY_HUD_MODULE_NAME);
            if (!cfg || typeof cfg !== "object") return;
            cfg.hudPosition = {
                x: Math.round(Number(abilityHudState.position.x) || 0),
                y: Math.round(Number(abilityHudState.position.y) || 0),
            };
            console.log("[HUD Position] Stored", { moduleName: ABILITY_HUD_MODULE_NAME, hudPosition: { ...cfg.hudPosition } });
            if (typeof saveSettings === "function") saveSettings();
        } catch (_) { }
    }

    function applyAbilityHudLiveConfig(opts = {}) {
        if (!abilityHudState.enabled) return;
        const cfg = opts.cfg && typeof opts.cfg === "object"
            ? getAbilityHudConfigFromRaw(opts.cfg)
            : getAbilityHudConfig();
        if (!abilityHudState.container) return;
        const panelRect = abilityHudState.container.getBoundingClientRect();
        const clamped = clampAbilityHudPosition(abilityHudState.position.x, abilityHudState.position.y, panelRect);
        abilityHudState.position.x = clamped.x;
        abilityHudState.position.y = clamped.y;
        abilityHudState.container.style.left = `${clamped.x}px`;
        abilityHudState.container.style.top = `${clamped.y}px`;
        abilityHudState.container.style.transformOrigin = "top left";
        abilityHudState.container.style.transform = `scale(${cfg.abilityHudScale})`;
        requestAbilityHudRender();
    }

    function getAbilityHudConfigFromRaw(rawCfg) {
        const mode = String(rawCfg?.abilityHudDisplayMode ?? ABILITY_HUD_CONFIG_DEFAULTS.abilityHudDisplayMode).trim().toLowerCase();
        abilityHudState.config.abilityHudDisplayMode = mode === "icons" ? "icons" : "list";
        abilityHudState.config.abilityHudScale = Math.max(0.75, Math.min(1.25, Number(rawCfg?.abilityHudScale) || ABILITY_HUD_CONFIG_DEFAULTS.abilityHudScale));
        abilityHudState.config.abilityHudGap = Math.max(1, Math.min(15, Number(rawCfg?.abilityHudGap) || ABILITY_HUD_CONFIG_DEFAULTS.abilityHudGap));
        abilityHudState.config.abilityHudShowPrices = parseBooleanSetting(rawCfg?.abilityHudShowPrices, ABILITY_HUD_CONFIG_DEFAULTS.abilityHudShowPrices);
        abilityHudState.config.abilityHudIconSize = Math.max(56, Math.min(164, Number(rawCfg?.abilityHudIconSize) || ABILITY_HUD_CONFIG_DEFAULTS.abilityHudIconSize));
        return { ...abilityHudState.config };
    }


    function getAbilityHudTextColor(hex) {
        const color = String(hex || "").trim();
        const match = color.match(/^#([0-9a-f]{6})$/i);
        if (!match) return "#ffffff";
        const raw = match[1];
        const r = parseInt(raw.slice(0, 2), 16);
        const g = parseInt(raw.slice(2, 4), 16);
        const b = parseInt(raw.slice(4, 6), 16);
        const luminance = (0.2126 * r) + (0.7152 * g) + (0.0722 * b);
        return luminance > 160 ? "#0a111d" : "#ffffff";
    }

    function createAbilityTile(index) {
        const tile = document.createElement("button");
        tile.type = "button";
        tile.dataset.slotIndex = String(index);
        tile.style.cssText = "appearance:none;position:relative;display:grid;grid-template-rows:auto 1fr auto;align-items:center;justify-items:center;gap:4px;width:96px;height:96px;border-radius:16px;border:1px solid rgba(255,255,255,.24);padding:7px;box-sizing:border-box;cursor:pointer;overflow:hidden;background:#2a2f3a;color:#fff;box-shadow:inset 0 -12px 20px rgba(0,0,0,.18),0 5px 14px rgba(0,0,0,.24);";

        // Enforced order: title (top) -> icon (center) -> price (bottom), all inside tile.
        const title = document.createElement("div");
        title.className = "zyrox-ability-title";
        title.style.cssText = "width:100%;text-align:center;font-size:11px;font-weight:800;line-height:1.1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.02em;text-shadow:0 1px 2px rgba(0,0,0,.45);z-index:2;";
        const icon = document.createElement("div");
        icon.className = "zyrox-ability-icon";
        icon.style.cssText = "display:flex;align-items:center;justify-content:center;width:44px;height:44px;min-width:44px;min-height:44px;max-width:44px;max-height:44px;font-size:29px;line-height:1;filter:drop-shadow(0 2px 3px rgba(0,0,0,.4));z-index:2;overflow:hidden;";
        const iconImg = document.createElement("img");
        iconImg.className = "zyrox-ability-icon-img";
        iconImg.alt = "";
        iconImg.style.cssText = "display:none;width:100%;height:100%;object-fit:contain;";
        const iconFallback = document.createElement("span");
        iconFallback.className = "zyrox-ability-icon-fallback";
        iconFallback.textContent = "◻";
        const iconFa = document.createElement("i");
        iconFa.className = "zyrox-ability-icon-fa";
        iconFa.setAttribute("aria-hidden", "true");
        iconFa.style.cssText = "display:none;font-size:28px;line-height:1;";
        icon.append(iconImg, iconFa, iconFallback);
        const price = document.createElement("div");
        price.className = "zyrox-ability-price";
        price.style.cssText = "width:100%;text-align:center;font-size:11px;font-weight:800;line-height:1.1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-shadow:0 1px 2px rgba(0,0,0,.45);z-index:2;";
        const overlay = document.createElement("div");
        overlay.style.cssText = "position:absolute;inset:0;pointer-events:none;background:linear-gradient(180deg,rgba(0,0,0,.18),rgba(0,0,0,.07) 42%,rgba(0,0,0,.25));z-index:1;";
        tile.append(title, icon, price, overlay);
        return { tile, title, icon, iconImg, iconFa, iconFallback, price };
    }

    function updateAbilityTileData(slot, ability) {
        const fallbackBg = "#2a2f3a";
        const fallbackIcon = "◻";
        const abilityName = ability?.displayName || ability?.name || "Unknown";
        const iconText = fallbackIcon;
        const iconRaw = typeof ability?.icon === "string" ? ability.icon.trim() : "";
        const bg = ability?.color?.background || fallbackBg;
        const textColor = ability?.color?.text || getAbilityHudTextColor(bg);
        if (!ability) {
            slot.tile.disabled = true;
            slot.tile.style.cursor = "default";
            slot.tile.style.opacity = ".52";
            slot.tile.style.background = fallbackBg;
            slot.tile.style.borderColor = "rgba(255,255,255,.16)";
            slot.title.textContent = "Empty";
            slot.iconImg.style.display = "none";
            slot.iconImg.removeAttribute("src");
            slot.iconFa.style.display = "none";
            slot.iconFa.className = "zyrox-ability-icon-fa";
            slot.iconFallback.style.display = "";
            slot.iconFallback.textContent = fallbackIcon;
            slot.price.textContent = "--";
            slot.title.style.color = "#d6dbea";
            slot.price.style.color = "#d6dbea";
            return;
        }
        const pricing = calculateAbilityCost(ability, { balance: abilityHudState.currentBalance });
        const alreadyPurchased = abilityHudState.purchasedAbilities.has(ability.name);
        const alreadyUsed = abilityHudState.usedAbilities.has(ability.name);
        const canAfford = abilityHudState.currentBalance >= pricing.roundedCost;
        const isTooExpensive = !alreadyPurchased && !canAfford;
        const disabled = alreadyUsed || isTooExpensive;
        slot.tile.disabled = disabled;
        slot.tile.style.opacity = alreadyUsed ? ".58" : (isTooExpensive ? ".68" : "1");
        slot.tile.style.cursor = disabled ? "default" : "pointer";
        slot.tile.style.background = bg;
        slot.tile.style.borderColor = alreadyUsed
            ? "rgba(140,146,160,.38)"
            : (isTooExpensive ? "rgba(172,158,128,.42)" : "rgba(255,255,255,.34)");
        slot.tile.style.filter = alreadyUsed
            ? "grayscale(0.7) saturate(0.45) brightness(0.74)"
            : (isTooExpensive ? "grayscale(0.45) saturate(0.6) brightness(0.8)" : "none");
        slot.title.textContent = abilityName;
        slot.title.title = abilityName;
        slot.title.style.color = textColor;
        slot.title.style.fontSize = abilityName.length > 14 ? "9px" : "11px";
        slot.icon.style.color = textColor;
        const isLikelyImage = /^https?:\/\//i.test(iconRaw) || /^data:image\//i.test(iconRaw) || iconRaw.startsWith("/");
        const isLikelyFaClass = /\bfa[srbld]?\b/i.test(iconRaw) || /\bfa-[a-z0-9-]+\b/i.test(iconRaw);
        if (isLikelyImage) {
            slot.iconImg.src = iconRaw;
            slot.iconImg.style.display = "";
            slot.iconFa.style.display = "none";
            slot.iconFa.className = "zyrox-ability-icon-fa";
            slot.iconFallback.style.display = "none";
        } else if (isLikelyFaClass) {
            slot.iconImg.style.display = "none";
            slot.iconImg.removeAttribute("src");
            slot.iconFa.className = `zyrox-ability-icon-fa ${iconRaw}`.trim();
            slot.iconFa.style.display = "";
            slot.iconFallback.style.display = "none";
        } else {
            slot.iconImg.style.display = "none";
            slot.iconImg.removeAttribute("src");
            slot.iconFa.style.display = "none";
            slot.iconFa.className = "zyrox-ability-icon-fa";
            slot.iconFallback.style.display = "";
            slot.iconFallback.textContent = iconText;
        }
        slot.iconFa.style.color = textColor;
        slot.iconFallback.style.color = textColor;
        const dimText = alreadyUsed ? "rgba(230,234,242,.95)" : (isTooExpensive ? "rgba(244,235,210,.95)" : textColor);
        slot.title.style.color = dimText;
        slot.icon.style.color = dimText;
        slot.iconFa.style.color = dimText;
        slot.iconFallback.style.color = dimText;
        const outlineShadow = alreadyUsed
            ? "0 1px 0 rgba(0,0,0,.8), 0 0 2px rgba(0,0,0,.7), 0 0 6px rgba(110,120,140,.45)"
            : (isTooExpensive ? "0 1px 0 rgba(0,0,0,.85), 0 0 2px rgba(0,0,0,.72), 0 0 6px rgba(184,152,86,.38)" : "0 1px 2px rgba(0,0,0,.45)");
        slot.title.style.textShadow = outlineShadow;
        slot.price.style.textShadow = outlineShadow;
        slot.icon.style.filter = alreadyUsed
            ? "drop-shadow(0 1px 1px rgba(0,0,0,.85)) drop-shadow(0 0 6px rgba(120,130,150,.38))"
            : (isTooExpensive ? "drop-shadow(0 1px 1px rgba(0,0,0,.88)) drop-shadow(0 0 6px rgba(191,150,76,.3))" : "drop-shadow(0 2px 3px rgba(0,0,0,.4))");
        const showPrices = abilityHudState.config.abilityHudShowPrices !== false;
        slot.price.textContent = showPrices ? (alreadyUsed ? "Used" : (alreadyPurchased ? "Use" : `$${pricing.roundedCost || 0}`)) : "";
        slot.price.style.display = showPrices ? "" : "none";
        slot.price.style.color = textColor;
        slot.tile.onclick = () => {
            if (alreadyPurchased) sendAbilityUse(ability);
            else sendAbilityPurchase(ability);
        };
    }

    function renderAbilityHudIcons(entries) {
        if (!abilityHudState.body) return;
        let row = abilityHudState.body.querySelector(".zyrox-ability-icon-row");
        if (!row) {
            abilityHudState.body.innerHTML = "";
            row = document.createElement("div");
            row.className = "zyrox-ability-icon-row";
            row.style.cssText = "display:grid;grid-template-columns:repeat(3,minmax(0,96px));gap:8px;justify-content:start;align-items:start;pointer-events:auto;width:max-content;";
            abilityHudState.body.appendChild(row);
            abilityHudState.iconTiles = [];
        }

        const slotCount = Math.max(3, entries.length);
        while (abilityHudState.iconTiles.length < slotCount) {
            const slot = createAbilityTile(abilityHudState.iconTiles.length);
            abilityHudState.iconTiles.push(slot);
            row.appendChild(slot.tile);
        }
        while (abilityHudState.iconTiles.length > slotCount) {
            const slot = abilityHudState.iconTiles.pop();
            slot?.tile?.remove();
        }

        const iconSize = abilityHudState.config.abilityHudIconSize;
        row.style.gap = `${abilityHudState.config.abilityHudGap}px`;
        for (let i = 0; i < slotCount; i += 1) {
            const slot = abilityHudState.iconTiles[i];
            if (slot?.tile) { slot.tile.style.width = `${iconSize}px`; slot.tile.style.height = `${iconSize}px`; }
            updateAbilityTileData(slot, entries[i] || null);
        }
    }

    function onAbilityHudInbound(event) {
        const packet = event?.detail;
        const key = packet?.key ?? packet?.payload?.key;
        if (key === "PLAYER_JOINS_STATIC_STATE") {
            abilityHudState.purchasedAbilities.clear();
            abilityHudState.usedAbilities.clear();
        }
        if (abilityHudState.packetLogCount < 18) {
            abilityHudState.packetLogCount += 1;
            console.debug(`${ABILITY_HUD_LOG} inbound packet`, {
                key,
                eventName: packet?.eventName,
                hasData: Boolean(packet?.data),
                dataKeys: packet?.data && typeof packet.data === "object" ? Object.keys(packet.data).slice(0, 12) : [],
            });
        }
        if (key === "PLAYER_JOINS_STATIC_STATE") {
            console.debug(`${ABILITY_HUD_LOG} static join packet intercepted`);
        }
        if (key === "STATE_UPDATE") {
            const type = packet?.data?.type ?? packet?.payload?.data?.type;
            if (type === "BALANCE") {
                const balance = Number(packet?.data?.value ?? packet?.payload?.data?.value);
                if (Number.isFinite(balance)) {
                    abilityHudState.currentBalance = balance;
                    requestAbilityHudRender();
                }
            }
            if (type === "PURCHASED_POWERUPS" || type === "USED_POWERUPS") {
                const list = packet?.data?.value ?? packet?.payload?.data?.value;
                if (Array.isArray(list)) {
                    const targetSet = type === "PURCHASED_POWERUPS" ? abilityHudState.purchasedAbilities : abilityHudState.usedAbilities;
                    let changed = false;
                    for (const entry of list) {
                        const abilityName = typeof entry === "string" ? entry.trim() : "";
                        if (!abilityName) continue;
                        if (!targetSet.has(abilityName)) {
                            targetSet.add(abilityName);
                            changed = true;
                        }
                    }
                    if (changed) requestAbilityHudRender();
                }
            }
        }
        if (packet?.eventName === "CLIENT_ID_SET") {
            const selfPlayerId = packet?.payload ?? packet?.data ?? null;
            if (typeof selfPlayerId === "string" && selfPlayerId.trim()) {
                abilityHudState.selfPlayerId = selfPlayerId.trim();
                console.debug(`${ABILITY_HUD_LOG} captured self player id from CLIENT_ID_SET`, { selfPlayerId: abilityHudState.selfPlayerId });
            }
        }
        if (key === "UPDATED_PLAYER_LEADERBOARD") {
            const pendingAbility = abilityHudState.pendingTargetAbility;
            const items = packet?.data?.items ?? packet?.payload?.data?.items;
            const rawPlayers = Array.isArray(items) ? items.filter((item) => item && item.id) : [];
            const players = rawPlayers.filter((item) => item.id !== abilityHudState.selfPlayerId);
            console.debug(`${ABILITY_HUD_LOG} [Step 3] received leaderboard packet`, {
                hasPendingAbility: Boolean(pendingAbility),
                selfPlayerId: abilityHudState.selfPlayerId,
                itemCountRaw: rawPlayers.length,
                itemCountFiltered: players.length,
            });
            if (pendingAbility && players.length) {
                openTargetSelectionMenu(pendingAbility, players);
            }
        }
        const abilities = extractAbilitiesFromPacket(packet);
        if (!abilities.length) {
            if (key === "PLAYER_JOINS_STATIC_STATE" || key === "STATE_UPDATE") {
                console.debug(`${ABILITY_HUD_LOG} no abilities extracted`, {
                    key,
                    probe: {
                        hasDataPowerups: Array.isArray(packet?.data?.powerups),
                        hasPayloadDataPowerups: Array.isArray(packet?.payload?.data?.powerups),
                        hasPayloadPowerups: Array.isArray(packet?.payload?.powerups),
                    },
                });
            }
            return;
        }
        console.debug(`${ABILITY_HUD_LOG} extracted abilities`, { key, count: abilities.length });
        let changed = false;
        for (const rawAbility of abilities) {
            const normalized = normalizeAbility(rawAbility);
            if (!normalized) continue;
            abilityHudState.abilities.set(normalized.name, normalized);
            changed = true;
            if (normalized.name === "Icer" || normalized.displayName === "Freezer") {
                console.debug(`${ABILITY_HUD_LOG} freeze mapping`, { displayName: normalized.displayName, purchaseName: normalized.name });
            }
        }
        if (changed) requestAbilityHudRender();
    }

    function onAbilityHudOutbound(event) {
        const packet = event?.detail;
        const key = packet?.key ?? packet?.payload?.key;
        if (key !== "POWERUP_PURCHASED" && key !== "POWERUP_ACTIVATED") return;
        const payload = packet?.payload || packet;
        console.debug(`${ABILITY_HUD_LOG} outbound powerup observed`, payload);
    }

    function sendAbilityPurchase(ability) {
        if (!ability?.name) return;
        if (abilityHudState.purchasedAbilities.has(ability.name) || abilityHudState.usedAbilities.has(ability.name)) return;
        const pricing = calculateAbilityCost(ability, { balance: abilityHudState.currentBalance });
        if (abilityHudState.currentBalance < pricing.roundedCost) return;
        const payload = { room: socketManager.blueboatRoomId, key: "POWERUP_PURCHASED", data: ability.name };
        console.debug(`${ABILITY_HUD_LOG} sending purchase payload`, payload);
        if (ability.name === "Icer") {
            console.debug(`${ABILITY_HUD_LOG} ASSERT freeze mapping ok: display="${ability.displayName}" payload="${ability.name}"`);
        }
        socketManager.sendMessage("POWERUP_PURCHASED", ability.name);
        abilityHudState.purchasedAbilities.add(ability.name);
        requestAbilityHudRender();
    }

    function isRebooterAbility(ability) {
        const name = String(ability?.name || "").trim().toLowerCase();
        const displayName = String(ability?.displayName || "").trim().toLowerCase();
        return name === "repurchasepowerups" || displayName === "rebooter";
    }

    function abilityRequiresTargetSelection(ability) {
        if (!ability || !Array.isArray(ability.disabled)) return false;
        const isShield = String(ability?.name || "").trim().toLowerCase() === "shield";
        const isGiftAbility = String(ability?.name || "").trim().toLowerCase() === "giving"
            || String(ability?.displayName || "").trim().toLowerCase() === "gift";
        const requires = (!isShield && ability.disabled.some((flag) => String(flag || "").trim() === "cleanOnly")) || isGiftAbility;
        console.debug(`${ABILITY_HUD_LOG} [Step 1] ability target-selection requirement`, {
            abilityName: ability?.name,
            disabledFlags: ability?.disabled,
            requiresTargetSelection: requires,
        });
        return requires;
    }

    function requestLeaderboardForAbilityTarget(ability) {
        const roomId = socketManager.blueboatRoomId;
        if (!roomId) {
            console.warn(`${ABILITY_HUD_LOG} [Step 2] missing room id; cannot request leaderboard`, { abilityName: ability?.name });
            return;
        }
        abilityHudState.pendingTargetAbility = ability;
        abilityHudState.pendingTargetRequestedAt = Date.now();
        const payload = { room: roomId, key: "PLAYER_LEADERBOARD_REQUESTED", data: null };
        console.debug(`${ABILITY_HUD_LOG} [Step 2] requesting leaderboard for target selection`, payload);
        socketManager.sendMessage("PLAYER_LEADERBOARD_REQUESTED", null);
    }

    function openTargetSelectionMenu(ability, players) {
        console.debug(`${ABILITY_HUD_LOG} [Step 3] opening target selection menu`, {
            abilityName: ability?.name,
            playerCount: players.length,
            players,
        });
        const existing = document.getElementById("zyrox-target-menu");
        if (existing) existing.remove();
        const overlay = document.createElement("div");
        overlay.id = "zyrox-target-menu";
        overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;";
        const panel = document.createElement("div");
        panel.style.cssText = "width:min(360px,calc(100vw - 20px));max-height:min(80vh,520px);overflow:auto;background:#121722;border:1px solid rgba(255,255,255,.2);border-radius:10px;padding:10px;font-family:Inter,system-ui,sans-serif;color:#fff;";
        const title = document.createElement("div");
        title.textContent = `Select target for ${ability.displayName || ability.name}`;
        title.style.cssText = "font-size:14px;font-weight:700;margin-bottom:8px;";
        panel.appendChild(title);
        players.forEach((player) => {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.textContent = `${player.name || "Unknown"}`;
            btn.style.cssText = "display:block;width:100%;text-align:left;margin:0 0 6px 0;padding:7px 8px;border-radius:8px;border:1px solid rgba(255,255,255,.2);background:rgba(255,255,255,.06);color:#fff;cursor:pointer;";
            btn.addEventListener("click", () => {
                overlay.remove();
                sendTargetedAbilityUse(ability, player.id);
            });
            panel.appendChild(btn);
        });
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.textContent = "Cancel";
        cancel.style.cssText = "display:block;width:100%;padding:7px 8px;border-radius:8px;border:1px solid rgba(255,255,255,.2);background:rgba(255,0,0,.2);color:#fff;cursor:pointer;";
        cancel.addEventListener("click", () => {
            console.debug(`${ABILITY_HUD_LOG} [Step 3] target selection canceled`, { abilityName: ability?.name });
            abilityHudState.pendingTargetAbility = null;
            overlay.remove();
        });
        panel.appendChild(cancel);
        overlay.appendChild(panel);
        overlay.addEventListener("click", (event) => {
            if (event.target === overlay) overlay.remove();
        });
        document.body.appendChild(overlay);
    }

    function sendTargetedAbilityUse(ability, targetId) {
        const roomId = socketManager.blueboatRoomId;
        if (!roomId || !ability?.name || !targetId) return;
        const data = { name: ability.name, target: targetId };
        const payload = { room: roomId, key: "POWERUP_ATTACK", data };
        console.debug(`${ABILITY_HUD_LOG} [Step 4] sending targeted ability payload`, payload);
        socketManager.sendMessage("POWERUP_ATTACK", data);
        abilityHudState.usedAbilities.add(ability.name);
        abilityHudState.pendingTargetAbility = null;
        requestAbilityHudRender();
    }

    function sendAbilityUse(ability) {
        if (!ability?.name) return;
        if (abilityHudState.usedAbilities.has(ability.name)) return;
        const activatePayload = { room: socketManager.blueboatRoomId, key: "POWERUP_ACTIVATED", data: ability.name };
        console.debug(`${ABILITY_HUD_LOG} [Step 0] sending regular activate payload`, activatePayload);
        socketManager.sendMessage("POWERUP_ACTIVATED", ability.name);

        if (abilityRequiresTargetSelection(ability)) {
            requestLeaderboardForAbilityTarget(ability);
            return;
        }

        if (isRebooterAbility(ability)) {
            console.debug(`${ABILITY_HUD_LOG} rebooter activated; clearing USED state while preserving PURCHASED state`);
            abilityHudState.usedAbilities.clear();
            abilityHudState.usedAbilities.add(ability.name);
            requestAbilityHudRender();
            return;
        }

        abilityHudState.usedAbilities.add(ability.name);
        requestAbilityHudRender();
    }

    function renderAbilityHud() {
        if (!abilityHudState.body) return;
        const entries = Array.from(abilityHudState.abilities.values());
        const cfg = getAbilityHudConfig();
        if (abilityHudState.container) {
            abilityHudState.container.style.transformOrigin = "top left";
            abilityHudState.container.style.transform = `scale(${cfg.abilityHudScale})`;
        }
        if (!entries.length) {
            abilityHudState.body.innerHTML = `<div style="font-size:12px;color:#b3b9c7;opacity:.85;">Waiting for abilities…</div>`;
            return;
        }
        if (cfg.abilityHudDisplayMode === "icons") {
            if (abilityHudState.container) {
                abilityHudState.container.style.width = "fit-content";
            }
            if (abilityHudState.body) {
                abilityHudState.body.style.width = "fit-content";
            }
            renderAbilityHudIcons(entries);
            return;
        }
        if (abilityHudState.container) abilityHudState.container.style.width = "min(360px,calc(100vw - 24px))";
        if (abilityHudState.body) abilityHudState.body.style.width = "";
        const frag = document.createDocumentFragment();
        for (const ability of entries) {
            const wrap = document.createElement("div");
            wrap.style.cssText = "display:flex;gap:8px;align-items:center;padding:6px 7px;border-radius:9px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);";
            const abilityDescription = typeof ability.description === "string" && ability.description.trim() ? ability.description.trim() : "No description available.";
            wrap.title = abilityDescription;
            const info = document.createElement("div");
            info.style.cssText = "display:flex;align-items:center;gap:8px;min-width:0;flex:1;";
            const name = document.createElement("div");
            name.style.cssText = "font-size:12px;font-weight:700;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;";
            name.textContent = ability.displayName;
            name.title = abilityDescription;
            const pricing = calculateAbilityCost(ability, { balance: abilityHudState.currentBalance });
            const canAfford = abilityHudState.currentBalance >= pricing.roundedCost;
            const showPrices = abilityHudState.config.abilityHudShowPrices !== false;
            info.append(name);
            const buyBtn = document.createElement("button");
            buyBtn.type = "button";
            const alreadyPurchased = abilityHudState.purchasedAbilities.has(ability.name);
            const alreadyUsed = abilityHudState.usedAbilities.has(ability.name);
            const disabled = alreadyUsed || (!alreadyPurchased && !canAfford);
            buyBtn.disabled = disabled;
            buyBtn.textContent = alreadyUsed
                ? "Used"
                : (alreadyPurchased ? "Use" : (showPrices ? `$${pricing.roundedCost}` : "Buy"));
            const isUsed = alreadyUsed;
            const isUnavailable = !alreadyPurchased && !canAfford;
            const buttonBorder = isUsed ? "rgba(160,160,160,.42)" : (isUnavailable ? "rgba(255,255,255,.24)" : "rgba(46,204,113,.82)");
            const buttonBg = isUsed ? "rgba(120,120,120,.36)" : (isUnavailable ? "rgba(255,255,255,.09)" : "rgba(46,204,113,.35)");
            const buttonColor = isUsed ? "rgba(230,230,230,.9)" : "#fff";
            buyBtn.className = "zyrox-upgrade-hud-button";
            buyBtn.style.cssText = `appearance:none;border:1px solid ${buttonBorder};background:${buttonBg};color:${buttonColor};border-radius:6px;padding:5px 10px;font-size:12px;font-weight:700;line-height:1;cursor:${disabled ? "default" : "pointer"};width:96px;min-width:96px;max-width:96px;text-align:center;opacity:${isUsed ? ".9" : (disabled ? ".72" : "1")};`;
            buyBtn.addEventListener("mousedown", (event) => {
                event.stopPropagation();
            });
            buyBtn.addEventListener("click", () => {
                if (alreadyPurchased) sendAbilityUse(ability);
                else sendAbilityPurchase(ability);
            });
            wrap.append(info, buyBtn);
            frag.appendChild(wrap);
        }
        abilityHudState.body.innerHTML = "";
        abilityHudState.body.appendChild(frag);
    }

    function startAbilityHud() {
        if (abilityHudState.enabled) return;
        abilityHudState.enabled = true;
        getAbilityHudConfig();
        if (!abilityHudState.wired) {
            abilityHudState.listeners = {
                inbound: (event) => onAbilityHudInbound(event),
                outbound: (event) => onAbilityHudOutbound(event),
            };
            socketManager.addEventListener("blueboatMessage", abilityHudState.listeners.inbound);
            socketManager.addEventListener("blueboatSend", abilityHudState.listeners.outbound);
            abilityHudState.wired = true;
        }
        const cfg = getAbilityHudConfig();
        const savedPos = readHudPosition(ABILITY_HUD_MODULE_NAME, null);
        if (savedPos && Number.isFinite(savedPos.x) && Number.isFinite(savedPos.y)) {
            abilityHudState.position.x = savedPos.x;
            abilityHudState.position.y = savedPos.y;
            console.debug(`${ABILITY_HUD_LOG} restored HUD position`, { saved: savedPos });
        }
        if (!Number.isFinite(abilityHudState.position.x) || !Number.isFinite(abilityHudState.position.y)) {
            const position = getAbilityHudDefaultPosition({ width: 360, height: 120 });
            abilityHudState.position.x = position.x;
            abilityHudState.position.y = position.y;
            console.debug(`${ABILITY_HUD_LOG} no saved HUD position; using default`, { position });
        }
        const panel = document.createElement("section");
        panel.style.cssText = `position:fixed;left:${abilityHudState.position.x}px;top:${abilityHudState.position.y}px;z-index:${ABILITY_HUD_INTERNAL_Z_INDEX};width:min(360px,calc(100vw - 24px));background:linear-gradient(170deg,rgba(17,21,30,${ABILITY_HUD_INTERNAL_OPACITY}),rgba(8,10,16,${ABILITY_HUD_INTERNAL_OPACITY}));border:1px solid rgba(255,255,255,.16);border-radius:12px;padding:8px;box-shadow:0 14px 34px rgba(0,0,0,.5);font-family:Inter,system-ui,sans-serif;cursor:grab;user-select:none;`;
        const head = document.createElement("header");
        head.style.cssText = "display:flex;align-items:center;justify-content:space-between;padding:4px 4px 8px 4px;border-bottom:1px solid rgba(255,255,255,.1);margin-bottom:8px;";
        head.innerHTML = `<div style="font-size:12px;font-weight:800;color:#fff;letter-spacing:.06em;">ABILITY HUD</div>`;
        const body = document.createElement("div");
        body.style.cssText = "display:flex;flex-direction:column;gap:5px;";
        panel.append(head, body);
        abilityHudState.container = panel;
        abilityHudState.body = body;
        document.documentElement.appendChild(panel);
        const clampedStart = clampAbilityHudPosition(abilityHudState.position.x, abilityHudState.position.y, panel.getBoundingClientRect());
        abilityHudState.position.x = clampedStart.x;
        abilityHudState.position.y = clampedStart.y;
        panel.style.left = `${clampedStart.x}px`;
        panel.style.top = `${clampedStart.y}px`;
        writeHudPosition(ABILITY_HUD_MODULE_NAME, clampedStart);
        console.debug(`${ABILITY_HUD_LOG} applied HUD position`, { applied: clampedStart });
        applyAbilityHudLiveConfig({ cfg });
        renderAbilityHud();
        panel.addEventListener("mousedown", (event) => {
            if (event.button !== 0) return;
            if (event.target?.closest?.("button")) return;
            abilityHudState.isDragging = true;
            abilityHudState.dragOffsetX = event.clientX - panel.offsetLeft;
            abilityHudState.dragOffsetY = event.clientY - panel.offsetTop;
            panel.style.cursor = "grabbing";
            event.preventDefault();
        });
        document.addEventListener("mousemove", abilityHudMouseMove);
        document.addEventListener("mouseup", abilityHudMouseUp);
        if (abilityHudBootstrap.latestPacket) {
            console.debug(`${ABILITY_HUD_LOG} hydrating from bootstrap cache`);
            onAbilityHudInbound({ detail: abilityHudBootstrap.latestPacket });
        }
        if (Number.isFinite(abilityHudBootstrap.latestBalance)) {
            abilityHudState.currentBalance = Number(abilityHudBootstrap.latestBalance) || 0;
        }
        if (abilityHudBootstrap.purchasedAbilities.size) {
            abilityHudState.purchasedAbilities = new Set(abilityHudBootstrap.purchasedAbilities);
        }
        if (abilityHudBootstrap.usedAbilities.size) {
            abilityHudState.usedAbilities = new Set(abilityHudBootstrap.usedAbilities);
        }
        if (abilityHudBootstrap.selfPlayerId) {
            abilityHudState.selfPlayerId = abilityHudBootstrap.selfPlayerId;
        }
        requestAbilityHudRender();
    }

    function abilityHudMouseMove(event) {
        if (!abilityHudState.isDragging || !abilityHudState.container) return;
        const rect = abilityHudState.container.getBoundingClientRect();
        const clamped = clampAbilityHudPosition(event.clientX - abilityHudState.dragOffsetX, event.clientY - abilityHudState.dragOffsetY, rect);
        abilityHudState.position.x = clamped.x;
        abilityHudState.position.y = clamped.y;
        abilityHudState.container.style.left = `${abilityHudState.position.x}px`;
        abilityHudState.container.style.top = `${abilityHudState.position.y}px`;
        writeHudPosition(ABILITY_HUD_MODULE_NAME, { x: Math.round(clamped.x), y: Math.round(clamped.y) });
    }

    function abilityHudMouseUp() {
        abilityHudState.isDragging = false;
        if (abilityHudState.container) abilityHudState.container.style.cursor = "grab";
        writeHudPosition(ABILITY_HUD_MODULE_NAME, abilityHudState.position);
        persistAbilityHudPosition();
    }

    function stopAbilityHud() {
        abilityHudState.enabled = false;
        if (abilityHudState.container) {
            abilityHudState.container.remove();
            abilityHudState.container = null;
            abilityHudState.body = null;
            abilityHudState.iconTiles = [];
        }
        if (abilityHudState.renderTimerId) {
            clearTimeout(abilityHudState.renderTimerId);
            abilityHudState.renderTimerId = null;
        }
        document.removeEventListener("mousemove", abilityHudMouseMove);
        document.removeEventListener("mouseup", abilityHudMouseUp);
    }

    const abilityHudBootstrap = {
        latestPacket: null,
        latestBalance: 0,
        purchasedAbilities: new Set(),
        usedAbilities: new Set(),
        selfPlayerId: null,
    };

    socketManager.addEventListener("blueboatMessage", (event) => {
        const packet = event?.detail;
        const key = packet?.key ?? packet?.payload?.key;

        if (packet?.eventName === "CLIENT_ID_SET") {
            const selfPlayerId = packet?.payload ?? packet?.data ?? null;
            if (typeof selfPlayerId === "string" && selfPlayerId.trim()) {
                abilityHudBootstrap.selfPlayerId = selfPlayerId.trim();
            }
        }

        if (!key) return;
        if (key === "PLAYER_JOINS_STATIC_STATE") {
            abilityHudBootstrap.latestPacket = packet;
            abilityHudBootstrap.usedAbilities.clear();
            const count = Array.isArray(packet?.data?.powerups) ? packet.data.powerups.length : 0;
            console.debug(`${ABILITY_HUD_LOG} bootstrap captured static state`, { count });
            return;
        }
        if (key === "STATE_UPDATE") {
            const type = packet?.data?.type ?? packet?.payload?.data?.type;
            if (type === "BALANCE") {
                const value = Number(packet?.data?.value ?? packet?.payload?.data?.value);
                if (Number.isFinite(value)) abilityHudBootstrap.latestBalance = value;
            }
            if (type === "PURCHASED_POWERUPS" || type === "USED_POWERUPS") {
                const list = packet?.data?.value ?? packet?.payload?.data?.value;
                if (Array.isArray(list)) {
                    const targetSet = type === "PURCHASED_POWERUPS" ? abilityHudBootstrap.purchasedAbilities : abilityHudBootstrap.usedAbilities;
                    targetSet.clear();
                    for (const item of list) {
                        const name = typeof item === "string" ? item.trim() : "";
                        if (name) targetSet.add(name);
                    }
                }
            }
            if (!abilityHudBootstrap.latestPacket) {
                abilityHudBootstrap.latestPacket = packet;
            }
        }
    });

    const MODULE_BEHAVIORS = {
        [ANIMATION_SKIP_MODULE_NAME]: {
            onEnable: startAnimationSkip,
            onDisable: stopAnimationSkip,
        },
        "ESP": {
            onEnable: startEsp,
            onDisable: stopEsp,
        },
        "Crosshair": {
            onEnable: startCrosshair,
            onDisable: stopCrosshair,
        },
        "Triggerbot (Autoshoot)": {
            onEnable: startTriggerAssist,
            onDisable: stopTriggerAssist,
        },
        "Aimbot": {
            onEnable: startAutoAim,
            onDisable: stopAutoAim,
        },
        "Answer Popup": {
            onEnable: startAnswerPopup,
            onDisable: stopAnswerPopup,
        },
        "Upgrade HUD": {
            onEnable: startUpgradeHud,
            onDisable: stopUpgradeHud,
        },
        "Auto Upgrade": {
            onEnable: startAutoUpgrade,
            onDisable: stopAutoUpgrade,
        },
        "Building HUD": {
            onEnable: startLavaBuildingHud,
            onDisable: stopLavaBuildingHud,
        },
        [ABILITY_HUD_MODULE_NAME]: {
            onEnable: startAbilityHud,
            onDisable: stopAbilityHud,
        },
        "Answer Reveal": {
            onEnable: startDrawItAnswerReveal,
            onDisable: stopDrawItAnswerReveal,
        },
        [TRUST_NO_ONE_MODULE_NAME]: {
            onEnable: startTrustNoOne,
            onDisable: stopTrustNoOne,
        },
        [CAMERA_ZOOM_MODULE_NAME]: {
            onEnable: startCameraZoom,
            onDisable: stopCameraZoom,
        },
        [HIDE_POPUPS_MODULE_NAME]: {
            onEnable: startHidePopups,
            onDisable: stopHidePopups,
        },
        [ANTI_AFK_MODULE_NAME]: {
            onEnable: startAntiAfk,
            onDisable: stopAntiAfk,
        },
    };
    const MODULE_DESCRIPTIONS = {
        "Auto Answer": "Automatically submits the best answer after a delay.",
        [ANIMATION_SKIP_MODULE_NAME]: "Skips most UI/menu animations (CSS + Web Animations API) so interfaces appear instantly.",
        "ESP": "Shows players with tracers, names, and off-screen indicators.",
        "Crosshair": "Draws a customizable crosshair and optional center line.",
        "Triggerbot (Autoshoot)": "Fires automatically when an enemy is in your aim radius.",
        "Aimbot": "Smoothly snaps your aim to nearby enemy players.",
        "Answer Reveal": "Reveals Draw It prompts/answers inside the drawing round.",
        "Answer Popup": "Displays detected Draw It answers in a popup.",
        [TRUST_NO_ONE_MODULE_NAME]: "Shows detected imposters in Trust No One.",
        "Upgrade HUD": "Shows Classic/Tycoon upgrade levels in a configurable HUD.",
        "Auto Upgrade": "Automatically buys the cheapest available Classic/Tycoon upgrade.",
        "Building HUD": "Shows Floor is Lava build costs and lets you buy builds quickly.",
        [ABILITY_HUD_MODULE_NAME]: "Shows intercepted abilities with live Classic/Tycoon pricing and one-click purchases.",
        [CAMERA_ZOOM_MODULE_NAME]: "Adjust how much you can see on the screen",
        [HIDE_POPUPS_MODULE_NAME]: "Hides Floor is Lava building purchase toasts and energy/resource popups.",
        [ANTI_AFK_MODULE_NAME]: "Sends lightweight synthetic activity pulses to reduce AFK kicks.",
    };

    // --- End of Core Utilities ---

    const MENU_LAYOUT = {
        general: {
            title: "General",
            groups: [
                {
                    name: "Core",
                    modules: [
                        {
                            name: "Auto Answer",
                            description: MODULE_DESCRIPTIONS["Auto Answer"],
                            settings: [
                                { id: "speed", label: "Answer Delay", type: "slider", min: 200, max: 3000, step: 50, default: 1000 },
                                { id: "triviaDelay", label: "Trivia Answer Delay", type: "slider", min: 0, max: 8000, step: 50, default: 1500 },
                            ],
                        },
                        {
                            name: ANTI_AFK_MODULE_NAME,
                            description: MODULE_DESCRIPTIONS[ANTI_AFK_MODULE_NAME],
                            settings: [
                                { id: "pulseMs", label: "Activity Pulse", type: "slider", min: 4000, max: 45000, step: 500, default: 12000 },
                            ],
                        },
                    ],
                },
                {
                    name: "Visual",
                    modules: [
                        {
                            name: "ESP",
                            description: MODULE_DESCRIPTIONS["ESP"],
                            settings: [
                                { id: "hitbox", label: "Hitbox", type: "checkbox", default: true },
                                { id: "hitboxSize", label: "Hitbox Size", type: "slider", min: 24, max: 270, step: 2, default: 150, unit: "px" },
                                { id: "hitboxWidth", label: "Hitbox Width", type: "slider", min: 1, max: 10, step: 1, default: 3, unit: "px" },
                                { id: "hitboxColor", label: "Hitbox Color", type: "color", default: "#ff3b3b" },
                                { id: "names", label: "Names", type: "checkbox", default: true },
                                { id: "namesDistanceOnly", label: "Distance Only", type: "checkbox", default: false },
                                { id: "nameSize", label: "Name Size", type: "slider", min: 10, max: 32, step: 1, default: 22, unit: "px" },
                                { id: "nameColor", label: "Name Color", type: "color", default: "#7a0c0c" },
                                {
                                    id: "offscreenStyle",
                                    label: "Off-screen Indicator",
                                    type: "select",
                                    default: "tracers",
                                    options: [
                                        { value: "none", label: "None" },
                                        { value: "tracers", label: "Tracers" },
                                        { value: "arrows", label: "Arrows" },
                                    ],
                                },
                                {
                                    id: "offscreenTheme",
                                    label: "Off-screen Theme",
                                    type: "select",
                                    default: "classic",
                                    options: [
                                        { value: "classic", label: "Classic" },
                                        { value: "dashed", label: "Dashed" },
                                        { value: "neon", label: "Neon" },
                                    ],
                                },
                                { id: "alwaysTracer", label: "Always Show Tracer", type: "checkbox", default: false },
                                { id: "tracerWidth", label: "Tracer Width", type: "slider", min: 1, max: 8, step: 1, default: 3, unit: "px" },
                                { id: "tracerColor", label: "Tracer Color", type: "color", default: "#ff3b3b" },
                                { id: "arrowSize", label: "Arrow Size", type: "slider", min: 8, max: 30, step: 1, default: 14, unit: "px" },
                                { id: "arrowColor", label: "Arrow Color", type: "color", default: "#ff3b3b" },
                                {
                                    id: "arrowStyle",
                                    label: "Arrow Style",
                                    type: "select",
                                    default: "regular",
                                    options: [
                                        { value: "regular", label: "Regular Arrow" },
                                        { value: "dot", label: "Dot" },
                                        { value: "modern", label: "Modern Arrow" },
                                    ],
                                },
                            ],
                        },
                        {
                            name: CAMERA_ZOOM_MODULE_NAME,
                            description: MODULE_DESCRIPTIONS[CAMERA_ZOOM_MODULE_NAME],
                            settings: [
                                { id: "zoom", label: "Zoom", type: "slider", min: CAMERA_ZOOM_MIN, max: CAMERA_ZOOM_MAX, step: CAMERA_ZOOM_STEP, default: CAMERA_ZOOM_DEFAULT, unit: "x" },
                            ],
                        },
                    ],
                },
                {
                    name: "Qol",
                    modules: [
                        {
                            name: ANIMATION_SKIP_MODULE_NAME,
                            description: MODULE_DESCRIPTIONS[ANIMATION_SKIP_MODULE_NAME],
                            settings: [],
                        },
                        {
                            name: HIDE_POPUPS_MODULE_NAME,
                            description: MODULE_DESCRIPTIONS[HIDE_POPUPS_MODULE_NAME],
                            settings: [
                                { id: "hideEnergyPopups", label: "Hide Energy Popup", type: "checkbox", default: true },
                                { id: "hideBuildingPopups", label: "Hide Building Popup", type: "checkbox", default: true },
                            ],
                        },
                    ],
                },
                {
                    name: "Combat",
                    modules: [
                        {
                            name: "Crosshair",
                            description: MODULE_DESCRIPTIONS["Crosshair"],
                            settings: [
                                { id: "enabled", label: "Show Crosshair", type: "checkbox", default: true },
                                {
                                    id: "style", label: "Style", type: "select", default: "x",
                                    options: [
                                        { value: "cross", label: "Cross (gap)" },
                                        { value: "solid", label: "Solid Cross" },
                                        { value: "crossdot", label: "Cross + Dot" },
                                        { value: "dot", label: "Dot" },
                                        { value: "circle", label: "Circle" },
                                        { value: "circlecross", label: "Circle + Cross" },
                                        { value: "plus", label: "Plus (thick)" },
                                        { value: "x", label: "X (diagonal)" },
                                    ],
                                },
                                { id: "color", label: "Crosshair Color", type: "color", default: "#ff3b3b" },
                                { id: "crosshairSize", label: "Crosshair Size", type: "slider", default: 25, min: 4, max: 40, step: 1, unit: "px" },
                                { id: "lineSize", label: "Cursor Width", type: "slider", default: 4, min: 1, max: 6, step: 0.5, unit: "px" },
                                { id: "showLine", label: "Show Line", type: "checkbox", default: false },
                                { id: "lineColor", label: "Line Color", type: "color", default: "#ff3b3b" },
                                { id: "tracerLineSize", label: "Tracer Thickness", type: "slider", default: 1.5, min: 0.5, max: 5, step: 0.5, unit: "px" },
                                { id: "hoverHighlight", label: "Player Hover", type: "checkbox", default: true },
                                { id: "hoverColor", label: "Hover Color", type: "color", default: "#ffff00" },
                                { id: "showCrosshairGlyph", label: "Show Actual Crosshair", type: "checkbox", default: true },
                            ],
                        },
                        {
                            name: "Triggerbot (Autoshoot)",
                            description: MODULE_DESCRIPTIONS["Triggerbot (Autoshoot)"],
                            settings: [
                                { id: "enabled", label: "Enabled", type: "checkbox", default: true },
                                { id: "teamCheck", label: "Ignore Teammates", type: "checkbox", default: true },
                                { id: "fovPx", label: "FOV Radius", type: "slider", default: 220, min: 8, max: 220, step: 1, unit: "px" },
                                { id: "holdToFire", label: "Hold Fire While Targeted", type: "checkbox", default: false },
                                { id: "fireRateMs", label: "Fire Rate Limit", type: "slider", default: 16, min: 16, max: 500, step: 1, unit: "ms" },
                                { id: "requireLOS", label: "Require LOS (future)", type: "checkbox", default: false },
                                { id: "onlyWhenGameFocused", label: "Only When Focused", type: "checkbox", default: true },
                                { id: "showTargetRing", label: "Show Target Ring", type: "checkbox", default: true },
                            ],
                        },
                        {
                            name: "Aimbot",
                            description: MODULE_DESCRIPTIONS["Aimbot"],
                            settings: [
                                { id: "enabled", label: "Enabled", type: "checkbox", default: true },
                                { id: "teamCheck", label: "Ignore Teammates", type: "checkbox", default: true },
                                { id: "fovDeg", label: "Aim FOV", type: "slider", default: 180, min: 15, max: 180, step: 1, unit: "°" },
                                { id: "smoothing", label: "Smoothing", type: "slider", default: 0, min: 0, max: 1, step: 0.01 },
                                { id: "maxStepPx", label: "Max Step", type: "slider", default: 120, min: 2, max: 120, step: 1, unit: "px" },
                                { id: "minStepPx", label: "Min Step", type: "slider", default: 0, min: 0, max: 8, step: 0.05, unit: "px" },
                                { id: "deadzonePx", label: "Deadzone", type: "slider", default: 0, min: 0, max: 12, step: 0.1, unit: "px" },
                                { id: "predictionMs", label: "Prediction", type: "slider", default: 0, min: 0, max: 220, step: 1, unit: "ms" },
                                { id: "lockMs", label: "Target Lock", type: "slider", default: 0, min: 0, max: 800, step: 5, unit: "ms" },
                                { id: "stickToTarget", label: "Stick To Target", type: "checkbox", default: false },
                                { id: "onlyWhenGameFocused", label: "Only When Focused", type: "checkbox", default: true },
                                { id: "requireMouseDown", label: "Require Left Mouse", type: "checkbox", default: false },
                                { id: "showDebugDot", label: "Show Debug Dot", type: "checkbox", default: true },
                            ],
                        },
                    ],
                },
            ],
        },
        gamemodeSpecific: {
            title: "Gamemode Specific",
            groups: [
                {
                    name: "Classic/Tycoon",
                    modules: [
                        {
                            name: "Upgrade HUD",
                            description: MODULE_DESCRIPTIONS["Upgrade HUD"],
                            settings: [
                                {
                                    id: "displayTitle",
                                    label: "Display Title",
                                    type: "checkbox",
                                    default: true,
                                },
                                {
                                    id: "showLvlPrefix",
                                    label: "Show Lvl Prefix",
                                    type: "checkbox",
                                    default: false,
                                },
                                {
                                    id: "showUpgradeButton",
                                    label: "Show Upgrade Button",
                                    type: "checkbox",
                                    default: true,
                                },
                                {
                                    id: "hudSize",
                                    label: "HUD Size",
                                    type: "slider",
                                    min: 60,
                                    max: 180,
                                    step: 5,
                                    default: 100,
                                    unit: "%",
                                },
                            ],
                        },
                        {
                            name: "Auto Upgrade",
                            description: MODULE_DESCRIPTIONS["Auto Upgrade"],
                            settings: [
                                { id: "multiplier", label: "Multiplier", type: "checkbox", default: true },
                                { id: "moneyPerQuestion", label: "Money / Question", type: "checkbox", default: true },
                                { id: "streakBonus", label: "Streak Bonus", type: "checkbox", default: true },
                                { id: "insurance", label: "Insurance", type: "checkbox", default: true },
                            ],
                        },
                        {
                            name: ABILITY_HUD_MODULE_NAME,
                            description: MODULE_DESCRIPTIONS[ABILITY_HUD_MODULE_NAME],
                            settings: [
                                { id: "abilityHudDisplayMode", label: "Display Mode", type: "select", default: "icons", options: [{ value: "icons", label: "Icons" }, { value: "list", label: "List" }] },
                                { id: "abilityHudScale", label: "Scale", type: "slider", min: 0.75, max: 1.25, step: 0.05, default: 0.9 },
                                { id: "abilityHudGap", label: "Icon Gap", type: "slider", min: 1, max: 15, step: 1, default: 5, unit: "px" },
                                { id: "abilityHudShowPrices", label: "Show Prices", type: "checkbox", default: true },
                            ],
                        },
                    ],
                },
                {
                    name: "Floor is Lava",
                    modules: [
                        {
                            name: "Building HUD",
                            description: MODULE_DESCRIPTIONS["Building HUD"],
                            settings: [
                                { id: "displayTitle", label: "Display Title", type: "checkbox", default: true },
                                { id: "hudSize", label: "HUD Size", type: "slider", min: 60, max: 180, step: 5, default: 100, unit: "%" },
                            ],
                        },
                    ],
                },
                {
                    name: "Draw It",
                    modules: [
                        {
                            name: "Answer Reveal",
                            description: MODULE_DESCRIPTIONS["Answer Reveal"],
                            settings: [
                                {
                                    id: "selectorMode",
                                    label: "Selector Mode",
                                    type: "select",
                                    default: "auto",
                                    options: [
                                        { value: "auto", label: "Auto" },
                                        { value: "strict", label: "Strict" },
                                    ],
                                },
                            ],
                        },
                        {
                            name: "Answer Popup",
                            description: MODULE_DESCRIPTIONS["Answer Popup"],
                            settings: [
                                {
                                    id: "preset",
                                    label: "Preset",
                                    type: "select",
                                    default: "default",
                                    options: [
                                        { value: "default", label: "Default (Red)" },
                                        { value: "green", label: "Green" },
                                        { value: "ice", label: "Ice" },
                                        { value: "grayscale", label: "Grayscale" },
                                    ],
                                },
                                { id: "text", label: "Popup Text", type: "text", default: "answer" },
                                { id: "durationMs", label: "Display Duration", type: "slider", min: 600, max: 8000, step: 100, default: 2600, unit: "ms" },
                                { id: "accent", label: "Accent Color", type: "color", default: "#ff4a4a" },
                                { id: "textColor", label: "Text Color", type: "color", default: "#ffffff" },
                            ],
                        },
                    ],
                },
                {
                    name: "Trust No One",
                    modules: [
                        {
                            name: TRUST_NO_ONE_MODULE_NAME,
                            description: MODULE_DESCRIPTIONS[TRUST_NO_ONE_MODULE_NAME],
                            settings: [],
                        },
                    ],
                },
            ],
        },
    };

    const state = {
        visible: true,
        searchQuery: "",
        shellWidth: 1160,
        shellHeight: 640,
        enabledModules: new Set(),
        moduleItems: new Map(),
        modulePanels: new Map(),
        moduleEntries: [],
        moduleConfig: new Map(),
        collapsedPanels: {},
        hiddenCategories: {},
        listeningForBind: null,
        listeningForMenuBind: false,
        searchAutofocus: true,
        displayMode: "loose",
        looseInitialized: false,
        loosePositions: {
            topbar: { x: 12, y: 12 },
        },
        loosePanelPositions: {},
        mergedRootPosition: { left: 20, top: 28 },
        globalPreset: "default",
        modules: new Map(),
    };

    // Bumped to v3 — includes display-mode and loose layout position persistence
    const STORAGE_KEY = "zyrox_client_settings_v3";
    const DEFAULT_FOOTER_HTML = () => `<span>Press <b>${CONFIG.toggleKey}</b> to show/hide menu</span><span>Right click modules for settings</span>`;

    function debounce(fn, waitMs = 120) {
        let timerId = null;
        return (...args) => {
            if (timerId) clearTimeout(timerId);
            timerId = setTimeout(() => {
                timerId = null;
                fn(...args);
            }, waitMs);
        };
    }

    // Defer all DOM work — WebSocket is already patched above at document-start.

    const WELCOME_POPUP_STORAGE_KEY = "zyroxWelcomePopupSeenV1";

    function showFirstLaunchWelcomePopup() {
        try {
            if (localStorage.getItem(WELCOME_POPUP_STORAGE_KEY) === "1") return;
        } catch (_) {
            return;
        }

        const overlay = document.createElement("div");
        overlay.style.cssText = [
            "position:fixed",
            "inset:0",
            "background:rgba(0,0,0,.52)",
            "display:flex",
            "align-items:center",
            "justify-content:center",
            "z-index:2147483647",
            "padding:18px",
            "font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif",
        ].join(";");

        const card = document.createElement("div");
        card.style.cssText = [
            "width:min(560px,100%)",
            "border-radius:14px",
            "border:1px solid rgba(255,255,255,.16)",
            "background:linear-gradient(165deg,rgba(31,31,36,.98),rgba(10,10,14,.98))",
            "box-shadow:0 20px 55px rgba(0,0,0,.5)",
            "padding:18px 20px",
            "color:#fff",
            "line-height:1.45",
        ].join(";");

        card.innerHTML = `
      <div style="margin:-18px -20px 14px -20px;padding:10px 14px;border-radius:14px 14px 0 0;border-bottom:1px solid rgba(255,255,255,.18);background:linear-gradient(125deg, rgba(255, 74, 74, 0.24), rgba(56, 16, 16, 0.9));display:flex;align-items:center;justify-content:space-between;gap:10px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <div style="font-size:13px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;">TEDDY client</div>
          <div style="font-size:12px;font-weight:700;opacity:.92;">v${CONFIG.version}</div>
        </div>
        <button type="button" class="zyrox-welcome-action" id="zyrox-welcome-x" aria-label="Close" style="appearance:none;width:24px;height:24px;border-radius:7px;border:1px solid rgba(255,255,255,.24);background:rgba(255,255,255,.08);color:#fff;font-size:14px;font-weight:800;line-height:1;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;transition:background .15s ease,border-color .15s ease,transform .15s ease;">×</button>
      </div>
      <div style="font-size:24px;font-weight:800;margin-bottom:10px;"><b>TEDDY client</b></div>
      <div style="font-size:15px;opacity:.92;margin-bottom:14px;">Welcome to <b>TEDDY client</b>: a modern hacked client / utility mod for gimkit.<br><br><b>Left-click</b> to enable/disable a module.<br><b>Right-click</b> to configure a modules settings.<br><b>'\\'</b> to hide/show the client.</div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
        <button type="button" class="zyrox-welcome-action" id="zyrox-welcome-close" style="margin-left:auto;appearance:none;padding:6px 10px;border-radius:8px;border:1px solid rgba(255,255,255,.24);background:rgba(255,255,255,.08);color:#fff;font-size:12px;font-weight:700;cursor:pointer;transition:background .15s ease,border-color .15s ease,transform .15s ease;">close</button>
      </div>
    `;

        const close = () => {
            try {
                localStorage.setItem(WELCOME_POPUP_STORAGE_KEY, "1");
            } catch (_) { }
            overlay.remove();
        };

        card.querySelector("#zyrox-welcome-close")?.addEventListener("click", close);
        card.querySelector("#zyrox-welcome-x")?.addEventListener("click", close);

        for (const action of card.querySelectorAll(".zyrox-welcome-action")) {
            action.addEventListener("mouseenter", () => {
                action.style.background = "rgba(255,255,255,.18)";
                action.style.borderColor = "rgba(255,255,255,.42)";
                action.style.transform = "translateY(-1px)";
            });
            action.addEventListener("mouseleave", () => {
                action.style.background = "rgba(255,255,255,.08)";
                action.style.borderColor = "rgba(255,255,255,.24)";
                action.style.transform = "translateY(0)";
            });
        }
        overlay.addEventListener("click", (event) => {
            if (event.target === overlay) close();
        });

        overlay.appendChild(card);
        document.documentElement.appendChild(overlay);
    }

    function initUi() {
        showFirstLaunchWelcomePopup();

        const style = document.createElement("style");
        style.textContent = `
    .zyrox-root,
    .zyrox-config-backdrop {
      --zyx-border: #ff6f6f99;
      --zyx-border-soft: rgba(255, 255, 255, 0.12);
      --zyx-text: #d6d6df;
      --zyx-text-strong: #fff;
      --zyx-header-text: #fff;
      --zyx-header-bg-start: rgba(255, 74, 74, 0.24);
      --zyx-header-bg-end: rgba(60, 18, 18, 0.92);
      --zyx-topbar-bg-start: rgba(255, 74, 74, 0.22);
      --zyx-topbar-bg-end: rgba(56, 16, 16, 0.9);
      --zyx-icon-color: #ffdada;
      --zyx-outline-color: #ff5b5bcc;
      --zyx-slider-color: #ff6b6b;
      --zyx-panel-count-text: #ffd9d9;
      --zyx-panel-count-border: rgba(255, 100, 100, 0.45);
      --zyx-panel-count-bg: rgba(8, 8, 10, 0.6);
      --zyx-settings-header-start: rgba(255, 61, 61, .3);
      --zyx-settings-header-end: rgba(45, 12, 12, .95);
      --zyx-settings-sidebar-bg: rgba(24, 24, 32, .22);
      --zyx-settings-body-bg: linear-gradient(180deg, rgba(18, 18, 22, 0.97), rgba(8, 8, 10, 0.97));
      --zyx-settings-text: #ffe5e5;
      --zyx-settings-subtext: #c2c2ce;
      --zyx-settings-card-bg: rgba(255,255,255,.03);
      --zyx-settings-card-border: rgba(255,255,255,.08);
      --zyx-select-bg: rgba(20, 20, 28, 0.9);
      --zyx-select-text: #ffe5e5;
      --zyx-input-bg: rgba(20, 20, 28, 0.9);
      --zyx-input-text: #ffe5e5;
      --zyx-accent-soft: #ffbdbd;
      --zyx-search-text: #ffe6e6;
      --zyx-checkmark-color: #ff6b6b;
      --zyx-module-hover-bg: rgba(30, 30, 36, 0.9);
      --zyx-module-hover-border: rgba(255, 255, 255, 0.14);
      --zyx-module-active-start: rgba(255, 61, 61, 0.32);
      --zyx-module-active-end: rgba(40, 10, 10, 0.8);
      --zyx-module-active-border: rgba(255, 61, 61, 0.52);
      --zyx-hover-shift: 2px;
      --zyx-shell-blur: 10px;
      --zyx-muted: #9b9bab;
      --zyx-shadow: 0 18px 48px rgba(0, 0, 0, 0.55);
      --zyx-radius-xl: 14px;
      --zyx-radius-lg: 12px;
      --zyx-radius-md: 10px;
      --zyx-font: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      /* FIX: button accent colours are now CSS variables, updated by applyAppearance() */
      --zyx-btn-bg: rgba(255, 61, 61, 0.12);
      --zyx-btn-hover-bg: rgba(255, 61, 61, 0.2);
    }

    .zyrox-root {
      all: initial;
      position: fixed;
      top: 28px;
      left: 20px;
      z-index: 2147483647;
      color: var(--zyx-text);
      user-select: none;
      font-family: var(--zyx-font);
    }

    .zyrox-root * { box-sizing: border-box; font-family: inherit; }

    .zyrox-config-backdrop {
      all: initial;
      position: fixed;
      inset: 0;
      z-index: 2147483648;
      background: rgba(0, 0, 0, 0.26);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--zyx-settings-text);
      font-family: var(--zyx-font);
    }

    .zyrox-config-backdrop * { box-sizing: border-box; font-family: inherit; }
    .zyrox-hidden { display: none !important; }

    .zyrox-shell {
      position: relative;
      display: inline-flex;
      flex-direction: column;
      gap: 10px;
      padding: 10px;
      width: 1160px;
      height: 640px;
      border-radius: var(--zyx-radius-xl);
      border: 1px solid var(--zyx-border-soft);
      background: linear-gradient(150deg, #ff3d3d22, rgba(0, 0, 0, 0.45));
      backdrop-filter: blur(var(--zyx-shell-blur)) saturate(115%);
      box-shadow: var(--zyx-shadow);
      overflow: auto;
    }

    .zyrox-topbar {
      min-height: 42px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 8px 12px;
      border-radius: var(--zyx-radius-lg);
      border: 1px solid var(--zyx-border);
      background: linear-gradient(125deg, var(--zyx-topbar-bg-start), var(--zyx-topbar-bg-end));
      cursor: move;
    }

    .zyrox-topbar-right {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Hide legacy topbar category controls from older builds/state */
    .zyrox-collapse-row,
    .zyrox-collapse-btn {
      display: none !important;
    }

    .zyrox-shell.loose-mode {
      padding: 0;
      width: auto !important;
      height: auto !important;
      min-width: 0;
      min-height: 0;
      border: none;
      box-shadow: none;
      background: transparent !important;
      backdrop-filter: none !important;
      overflow: visible;
    }

    .zyrox-shell.loose-mode .zyrox-footer,
    .zyrox-shell.loose-mode .zyrox-resize-handle {
      display: none;
    }

    .zyrox-shell.loose-mode .zyrox-topbar {
      position: absolute;
      top: 0;
      left: 0;
      width: fit-content;
      min-height: 38px;
      padding: 6px 10px;
      z-index: 4;
    }

    .zyrox-topbar {
      display: none !important;
    }

    .zyrox-shell.loose-mode .zyrox-section {
      display: contents;
    }

    .zyrox-shell.loose-mode .zyrox-section-label {
      display: none;
    }

    .zyrox-shell.loose-mode .zyrox-panels {
      display: block;
      overflow: visible;
      max-height: none;
      padding: 0;
    }

    .zyrox-shell.loose-mode .zyrox-panel {
      position: absolute;
      width: 212px;
      z-index: 3;
    }

    .zyrox-shell.loose-mode .zyrox-panel-header {
      cursor: move;
    }


    .zyrox-brand { display: flex; align-items: center; gap: 10px; color: var(--zyx-text-strong); }

    .zyrox-logo {
      width: 30px;
      height: 30px;
      border-radius: 6px;
      object-fit: contain;
      box-shadow: 0 0 0 1px rgba(255,255,255,.25), 0 0 18px rgba(255,61,61,.45);
      outline: 1px solid var(--zyx-icon-color);
    }

    .zyrox-brand .title { font-size: 13px; font-weight: 700; line-height: 1; }
    .zyrox-brand .subtitle { font-size: 10px; font-weight: 500; color: rgba(255,255,255,.7); }

    .zyrox-chip {
      font-size: 10px;
      color: var(--zyx-settings-text);
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--zyx-outline-color);
      border-radius: 999px;
      padding: 4px 8px;
      line-height: 1;
    }

    .zyrox-keybind-btn {
      font-size: 10px;
      color: var(--zyx-icon-color);
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--zyx-outline-color);
      border-radius: 8px;
      padding: 4px 8px;
      line-height: 1;
      cursor: pointer;
    }

    .zyrox-settings-btn {
      width: 30px;
      height: 30px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 15px;
      color: var(--zyx-icon-color);
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--zyx-outline-color);
      border-radius: 8px;
      line-height: 1;
      cursor: pointer;
      padding: 0;
    }

    .zyrox-search {
      width: 190px;
      height: 28px;
      border-radius: 8px;
      border: 1px solid var(--zyx-outline-color);
      background: rgba(10, 8, 8, 0.72);
      color: var(--zyx-search-text);
      padding: 0 10px;
      font-size: 12px;
      outline: none;
    }

    .zyrox-search:focus {
      background: rgba(15, 12, 12, 0.8);
      border-color: rgba(255, 255, 255, 0.15);
    }

    .zyrox-section { display: flex; flex-direction: column; gap: 7px; }
    .zyrox-section-label {
      font-size: 10px;
      letter-spacing: 0.25px;
      color: var(--zyx-accent-soft);
      padding-left: 2px;
      text-transform: uppercase;
    }

    .zyrox-panels {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: flex-start;
      align-content: flex-start;
      overflow: auto;
      max-width: 100%;
      padding-bottom: 2px;
      max-height: 38vh;
    }

    /* FIX: was hardcoded rgba(255, 61, 61, 0.3) — now follows theme */
    .zyrox-panels::-webkit-scrollbar { width: 8px; height: 8px; }
    .zyrox-panels::-webkit-scrollbar-thumb { background: var(--zyx-btn-hover-bg); border-radius: 999px; }

    .zyrox-panel {
      width: 212px;
      border-radius: var(--zyx-radius-lg);
      border: 1px solid var(--zyx-border-soft);
      background: linear-gradient(180deg, rgba(24, 24, 30, 0.9), rgba(10, 10, 12, 0.9));
      overflow: hidden;
    }

    .zyrox-panel-header {
      min-height: 33px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 10px;
      font-size: 12px;
      font-weight: 600;
      color: var(--zyx-header-text);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      background: linear-gradient(90deg, var(--zyx-header-bg-start), var(--zyx-header-bg-end));
    }

    .zyrox-panel-collapse-btn {
      font-size: 14px;
      color: var(--zyx-panel-count-text);
      background: transparent;
      border: none;
      padding: 0;
      line-height: 1;
      cursor: pointer;
      user-select: none;
    }

    .zyrox-panel-collapse-btn.collapsed {
      opacity: 0.62;
    }

    .zyrox-hidden-categories-list {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }

    .zyrox-hidden-category-btn {
      border: 1px solid var(--zyx-outline-color);
      border-radius: 10px;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.07), rgba(0, 0, 0, 0.16));
      color: var(--zyx-settings-text);
      padding: 6px 11px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.2px;
      cursor: pointer;
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.06);
      transition: background .12s ease, border-color .12s ease, opacity .12s ease, transform .12s ease;
    }

    .zyrox-hidden-category-btn:hover {
      background: linear-gradient(180deg, var(--zyx-btn-hover-bg), rgba(0, 0, 0, 0.22));
      border-color: var(--zyx-panel-count-border);
      transform: translateY(-1px);
    }

    .zyrox-hidden-category-btn.is-hidden {
      opacity: 0.72;
      text-decoration: line-through;
      border-color: rgba(255, 120, 120, 0.44);
      background: linear-gradient(180deg, rgba(255, 80, 80, 0.18), rgba(55, 0, 0, 0.2));
    }

    .zyrox-module-list { margin: 0; padding: 7px; list-style: none; display: flex; flex-direction: column; gap: 5px; }

    .zyrox-module {
      min-height: 30px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 0 10px;
      font-size: 13px;
      font-weight: 500;
      color: var(--zyx-text);
      border: 1px solid transparent;
      border-radius: var(--zyx-radius-md);
      background: rgba(255, 255, 255, 0.03);
      transition: transform .11s ease, background .11s ease, border-color .11s ease, color .11s ease;
      cursor: pointer;
      white-space: nowrap;
    }

    .zyrox-module:hover {
      background: var(--zyx-module-hover-bg);
      border-color: var(--zyx-module-hover-border);
      color: var(--zyx-settings-text);
      transform: translateX(var(--zyx-hover-shift));
    }

    .zyrox-module.active {
      color: #fff;
      background: linear-gradient(90deg, var(--zyx-module-active-start), var(--zyx-module-active-end));
      border-color: var(--zyx-module-active-border);
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.06);
    }

    .zyrox-bind-label {
      font-size: 10px;
      color: var(--zyx-muted);
      border: 1px solid rgba(255, 255, 255, 0.14);
      border-radius: 6px;
      padding: 2px 5px;
      line-height: 1;
      background: rgba(0, 0, 0, 0.35);
    }

    .zyrox-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      color: var(--zyx-muted);
      font-size: 10px;
      padding: 0 3px;
    }

    .zyrox-config {
      position: relative;
      z-index: 2147483649;
      width: min(460px, 92vw);
      min-width: 340px;
      border-radius: 11px;
      border: 1px solid var(--zyx-border);
      background: linear-gradient(180deg, rgba(18, 18, 22, 0.97), rgba(8, 8, 10, 0.97));
      box-shadow: var(--zyx-shadow);
      overflow: hidden;
    }

    .zyrox-config.hidden { display: none !important; }
    /* FIX: config header now uses settings-header vars so it follows the theme */
    .zyrox-config-header { padding: 10px 72px 10px 12px; border-bottom: 1px solid rgba(255,255,255,.09); background: linear-gradient(90deg, var(--zyx-settings-header-start), var(--zyx-settings-header-end)); }
    .zyrox-config-title { color: var(--zyx-settings-text); font-size: 12px; font-weight: 700; margin-bottom: 2px; line-height: 1.2; }
    .zyrox-config-sub { color: var(--zyx-settings-subtext); font-size: 11px; line-height: 1.2; }
    .zyrox-config-body { padding: 13px; color: var(--zyx-settings-text); }
    .zyrox-config-row { display:flex; justify-content:space-between; align-items:center; gap:8px; color:var(--zyx-settings-text); font-size:14px; }
    .zyrox-config-actions { display: flex; align-items: center; gap: 6px; }

    /* FIX: was hardcoded rgba(255, 61, 61, ...) — now reads CSS variables set by applyAppearance() */
    .zyrox-btn {
      border: 1px solid var(--zyx-outline-color);
      background: var(--zyx-btn-bg);
      color: var(--zyx-settings-text);
      border-radius: 8px;
      padding: 7px 10px;
      font-size: 12px;
      cursor: pointer;
    }

    .zyrox-btn:hover { background: var(--zyx-btn-hover-bg); color: #fff; }

    .zyrox-btn-square {
      width: 33px;
      height: 33px;
      padding: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      line-height: 1;
      font-size: 16px;
      color: var(--zyx-icon-color);
    }

    .zyrox-config-backdrop.hidden { display: none !important; }

    .zyrox-settings {
      position: relative;
      z-index: 2147483649;
      width: min(760px, 92vw);
      height: min(620px, 88vh);
      border-radius: 12px;
      border: 1px solid var(--zyx-border);
      background: var(--zyx-settings-body-bg);
      box-shadow: var(--zyx-shadow);
      overflow: hidden;
      color: var(--zyx-settings-text);
      font-family: var(--zyx-font);
      display: flex;
      flex-direction: column;
    }

    .zyrox-config {
      font-family: var(--zyx-font);
    }

    .esp-value-text {
      font-family: var(--zyx-font);
      font-size: 0.85em;
    }

    .zyrox-settings.hidden { display: none !important; }
    .zyrox-settings-header { padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,.09); background: linear-gradient(90deg, var(--zyx-settings-header-start), var(--zyx-settings-header-end)); }
    .zyrox-settings-title { font-size: 16px; font-weight: 700; margin-bottom: 4px; color: var(--zyx-settings-text); }
    .zyrox-settings-sub { font-size: 12px; color: var(--zyx-settings-subtext); }
    .zyrox-settings-layout { display: grid; grid-template-columns: 150px 1fr; min-height: 0; flex: 1; }
    .zyrox-settings-sidebar {
      border-right: 1px solid rgba(255,255,255,.08);
      padding: 10px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      background: var(--zyx-settings-sidebar-bg);
    }
    .zyrox-settings-tab {
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 8px;
      padding: 7px 8px;
      font-size: 12px;
      color: var(--zyx-settings-text);
      background: rgba(0,0,0,.2);
      text-align: left;
      cursor: pointer;
    }
    .zyrox-settings-tab.active {
      border-color: var(--zyx-outline-color);
      background: color-mix(in srgb, var(--zyx-topbar-bg-start) 75%, transparent);
      color: #fff;
    }
    .zyrox-settings-pane { min-height: 0; display: flex; }
    .zyrox-settings-body { padding: 14px; display: flex; flex-direction: column; gap: 8px; overflow: auto; min-height: 0; width: 100%; }
    .zyrox-settings-body::-webkit-scrollbar { width: 10px; }
    .zyrox-settings-body::-webkit-scrollbar-thumb { background: color-mix(in srgb, var(--zyx-outline-color) 70%, transparent); border-radius: 999px; }
    .zyrox-settings-pane.hidden { display: none !important; }
    .zyrox-setting-card { border: 1px solid var(--zyx-settings-card-border); border-radius: 10px; padding: 8px 10px; background: var(--zyx-settings-card-bg); display:flex; align-items:center; justify-content:space-between; gap:10px; }
    .zyrox-setting-card label { display:block; font-size: 12px; color: var(--zyx-settings-text); margin: 0; }
    .zyrox-setting-card input[type="text"],
    .zyrox-config-body input[type="text"] {
      background: var(--zyx-input-bg);
      color: var(--zyx-input-text);
      border: 1px solid var(--zyx-settings-card-border);
      border-radius: 8px;
      padding: 6px 8px;
      min-width: 150px;
    }
    .zyrox-setting-card input[type='color'] {
      width: 52px;
      height: 30px;
      border: 1px solid rgba(255,255,255,.2);
      border-radius: 8px;
      background: transparent;
      cursor: pointer;
      overflow: hidden;
      padding: 0;
    }
    .zyrox-setting-card input[type='range'] { width: 190px; accent-color: var(--zyx-slider-color); }
    .zyrox-setting-card input[type='checkbox'] { width: 16px; height: 16px; accent-color: var(--zyx-checkmark-color); }
    .zyrox-setting-card select {
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      border: 1px solid var(--zyx-settings-card-border);
      background: var(--zyx-select-bg);
      background-image:
        linear-gradient(45deg, transparent 50%, var(--zyx-select-text) 50%),
        linear-gradient(135deg, var(--zyx-select-text) 50%, transparent 50%);
      background-position:
        calc(100% - 14px) calc(50% - 2px),
        calc(100% - 8px) calc(50% - 2px);
      background-size: 6px 6px, 6px 6px;
      background-repeat: no-repeat;
      color: var(--zyx-select-text);
      border-radius: 8px;
      padding: 6px 26px 6px 8px;
      font-size: 12px;
      min-height: 30px;
    }
    .zyrox-setting-card select:focus {
      outline: 1px solid var(--zyx-outline-color);
      outline-offset: 1px;
    }
    .zyrox-setting-card select option {
      background: var(--zyx-select-bg);
      color: var(--zyx-select-text);
    }
    .zyrox-gradient-pair { display: inline-flex; align-items: center; gap: 8px; }
    .zyrox-preset-header { font-size: 10px; text-transform: uppercase; letter-spacing: .35px; color: var(--zyx-accent-soft); margin-bottom: 4px; }
    .zyrox-preset-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 2px; }
    .zyrox-preset-btn { border: 1px solid var(--zyx-outline-color); background: rgba(0,0,0,.26); color: var(--zyx-settings-text); border-radius: 8px; padding: 6px 10px; font-size: 10px; cursor: pointer; }
    .zyrox-preset-btn .preset-swatch { display:inline-block; width:10px; height:10px; border-radius:999px; margin-right:6px; border:1px solid rgba(255,255,255,.3); vertical-align:-1px; }
    .zyrox-preset-btn:hover { background: var(--zyx-btn-hover-bg); }
    .zyrox-subheading {
      grid-column: 1 / -1;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.25px;
      color: var(--zyx-accent-soft);
      margin-top: -2px;
      margin-bottom: -4px;
    }
    .zyrox-about-content {
      display: flex;
      flex-direction: column;
      gap: 10px;
      font-size: 12px;
      color: var(--zyx-settings-subtext);
      line-height: 1.45;
      user-select: text;
    }
    .zyrox-about-content b {
      color: var(--zyx-settings-text);
      font-weight: 700;
    }
    .zyrox-about-source-btn {
      align-self: flex-start;
      text-decoration: none;
      margin-top: 4px;
    }
    .zyrox-settings-actions { display:flex; justify-content:space-between; align-items:flex-end; gap:8px; padding: 8px 14px 14px; }
    .zyrox-settings-actions-group { display:flex; gap:8px; }
    .zyrox-settings-action-btn {
      min-height: 31px;
      line-height: 1.1;
      white-space: nowrap;
    }
    .zyrox-config-header-actions {
      position: absolute;
      top: 8px;
      right: 8px;
      display: inline-flex;
      gap: 4px;
    }
    .zyrox-config-header-actions .zyrox-close-btn {
      position: static;
    }
    .config-reset-btn {
      width: auto;
      min-width: 44px;
      height: 20px;
      padding: 0 5px;
      font-size: 9px;
      text-transform: lowercase;
      background: rgba(0, 0, 0, 0.16);
      border-color: rgba(255, 255, 255, 0.22);
      color: rgba(255, 255, 255, 0.84);
    }
    .zyrox-close-btn {
      position: absolute;
      top: 8px;
      right: 8px;
      width: 20px;
      height: 20px;
      border-radius: 5px;
      border: 1px solid var(--zyx-outline-color);
      background: rgba(0, 0, 0, 0.25);
      color: var(--zyx-icon-color);
      cursor: pointer;
      padding: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      line-height: 1;
      font-size: 12px;
    }

    .zyrox-resize-handle {
      position: absolute;
      right: 2px;
      bottom: 2px;
      width: 14px;
      height: 14px;
      cursor: nwse-resize;
      border-right: 2px solid rgba(255, 110, 110, 0.85);
      border-bottom: 2px solid rgba(255, 110, 110, 0.85);
      border-radius: 0 0 8px 0;
      opacity: 0.9;
    }

    /* Theme layout styles */
    .zyrox-theme-layout {
      display: grid;
      grid-template-columns: 180px 1fr;
      min-height: 0;
      height: 100%;
    }
    .zyrox-theme-sidebar {
      border-right: 1px solid rgba(255,255,255,.08);
      padding: 14px;
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      background: var(--zyx-settings-sidebar-bg);
      overflow-y: auto;
    }
    .zyrox-theme-sidebar::-webkit-scrollbar {
      width: 6px;
    }
    .zyrox-theme-sidebar::-webkit-scrollbar-thumb {
      background: color-mix(in srgb, var(--zyx-outline-color) 50%, transparent);
      border-radius: 999px;
    }
    .zyrox-theme-categories {
      display: flex;
      flex-direction: column;
      gap: 6px;
      width: 100%;
    }
    .zyrox-theme-category {
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 8px;
      padding: 8px 10px;
      font-size: 10px;
      color: var(--zyx-settings-text);
      background: rgba(0,0,0,.2);
      text-align: left;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .zyrox-theme-category:hover {
      background: var(--zyx-btn-hover-bg);
      border-color: rgba(255,255,255,.2);
    }
    .zyrox-theme-category.active {
      border-color: var(--zyx-outline-color);
      background: color-mix(in srgb, var(--zyx-topbar-bg-start) 75%, transparent);
      color: #fff;
    }
    .zyrox-theme-content {
      padding: 14px;
      overflow-y: auto;
      min-height: 0;
    }
    .zyrox-theme-content::-webkit-scrollbar {
      width: 10px;
    }
    .zyrox-theme-content::-webkit-scrollbar-thumb {
      background: color-mix(in srgb, var(--zyx-outline-color) 70%, transparent);
      border-radius: 999px;
    }
    .zyrox-theme-section {
      display: none;
      flex-direction: column;
      gap: 8px;
    }
    .zyrox-theme-section.active {
      display: flex;
    }
  `;

        const root = document.createElement("div");
        root.className = "zyrox-root";

        const shell = document.createElement("div");
        shell.className = "zyrox-shell";

        const topbar = document.createElement("div");
        topbar.className = "zyrox-topbar";
        topbar.innerHTML = `
    <div class="zyrox-brand">
      <img class="zyrox-logo" src="${CONFIG.logoUrl}" alt="Zyrox logo" />
      <div>
        <div class="title">${CONFIG.title}</div>
        <div class="subtitle">${CONFIG.subtitle}</div>
      </div>
    </div>
    <div class="zyrox-collapse-row"></div>
    <div class="zyrox-topbar-right">
      <input class="zyrox-search" type="text" placeholder="Search utilities..." autocomplete="off" />
      <button class="zyrox-settings-btn" type="button" title="Open client settings">⚙</button>
      <span class="zyrox-chip">v${CONFIG.version}</span>
    </div>
  `;

        const searchInput = topbar.querySelector(".zyrox-search");
        const settingsBtn = topbar.querySelector(".zyrox-settings-btn");
        const collapseRow = topbar.querySelector(".zyrox-collapse-row");

        const generalSection = document.createElement("section");
        generalSection.className = "zyrox-section";
        generalSection.innerHTML = `<div class="zyrox-section-label">General</div>`;

        const gamemodeSection = document.createElement("section");
        gamemodeSection.className = "zyrox-section";
        gamemodeSection.innerHTML = `<div class="zyrox-section-label">Gamemode Specific</div>`;

        const footer = document.createElement("div");
        footer.className = "zyrox-footer";
        setFooterText();

        const resizeHandle = document.createElement("div");
        resizeHandle.className = "zyrox-resize-handle";

        const configMenu = document.createElement("div");
        configMenu.className = "zyrox-config hidden";
        configMenu.innerHTML = `
    <div class="zyrox-config-header">
      <div class="zyrox-config-title">Module Config</div>
      <div class="zyrox-config-sub">Configure this module.</div>
    </div>
    <div class="zyrox-config-header-actions">
      <button class="zyrox-close-btn config-reset-btn" type="button" title="Reset module config">reset</button>
      <button class="zyrox-close-btn config-close-btn" type="button" title="Close">✕</button>
    </div>
    <div class="zyrox-config-body">
      <div class="zyrox-config-row">
        <span>Keybind</span>
        <div class="zyrox-config-actions">
          <button class="zyrox-btn zyrox-btn-square" type="button" title="Reset keybind">↺</button>
          <button class="zyrox-btn" type="button">Set keybind</button>
        </div>
      </div>
    </div>
  `;

        const configBackdrop = document.createElement("div");
        configBackdrop.className = "zyrox-config-backdrop hidden";
        configBackdrop.appendChild(configMenu);

        const settingsMenu = document.createElement("div");
        settingsMenu.className = "zyrox-settings hidden";
        settingsMenu.innerHTML = `
    <div class="zyrox-settings-header">
      <div class="zyrox-settings-title">Client Settings</div>
      <div class="zyrox-settings-sub">Customize colors and appearance</div>
    </div>
    <button class="zyrox-close-btn settings-close-top" type="button" title="Close">✕</button>
    <div class="zyrox-settings-layout">
      <div class="zyrox-settings-sidebar">
        <button class="zyrox-settings-tab active" type="button" data-tab="controls">Controls</button>
        <button class="zyrox-settings-tab" type="button" data-tab="theme">Theme</button>
        <button class="zyrox-settings-tab" type="button" data-tab="appearance">Appearance</button>
        <button class="zyrox-settings-tab" type="button" data-tab="about">About</button>
      </div>
      <div class="zyrox-settings-pane" data-pane="controls">
        <div class="zyrox-settings-body">
          <div class="zyrox-subheading">Menu</div>
          <div class="zyrox-setting-card">
            <label>Menu Toggle Key</label>
            <button class="zyrox-keybind-btn settings-menu-key" type="button">Menu Key: ${CONFIG.toggleKey}</button>
            <button class="zyrox-btn zyrox-btn-square settings-menu-key-reset" type="button" title="Reset menu key">↺</button>
          </div>
          <div class="zyrox-subheading">Search</div>
          <div class="zyrox-setting-card">
            <label>Auto Focus Search</label>
            <input type="checkbox" class="set-search-autofocus" checked />
          </div>
          <div class="zyrox-subheading">Modules</div>
          <div class="zyrox-setting-card">
            <label>Hidden Categories (click to toggle)</label>
            <div class="zyrox-hidden-categories-list"></div>
          </div>
        </div>
      </div>
      <div class="zyrox-settings-pane hidden" data-pane="theme">
        <div class="zyrox-settings-body">
          <div class="zyrox-subheading">Presets</div>
          <div class="zyrox-preset-row" style="margin-bottom: 14px;">
            <button type="button" class="zyrox-preset-btn" data-preset="default"><span class="preset-swatch" style="background:#ff3d3d"></span>Default</button>
            <button type="button" class="zyrox-preset-btn" data-preset="green"><span class="preset-swatch" style="background:#2dff75"></span>Green</button>
            <button type="button" class="zyrox-preset-btn" data-preset="ice"><span class="preset-swatch" style="background:#6cd8ff"></span>Ice</button>
            <button type="button" class="zyrox-preset-btn" data-preset="grayscale"><span class="preset-swatch" style="background:#bfbfbf"></span>Greyscale</button>
          </div>
          <div class="zyrox-subheading">Display Mode</div>
          <div class="zyrox-settings-actions-group" style="margin-bottom: 14px; margin-top: 8px;">
            <button class="zyrox-btn set-display-mode" data-display-mode="merged" type="button">Merged</button>
            <button class="zyrox-btn set-display-mode active" data-display-mode="loose" type="button">Loose</button>
          </div>
        </div>
      </div>
      <div class="zyrox-settings-pane hidden" data-pane="appearance">
        <div class="zyrox-settings-body">
          <div class="zyrox-subheading">Layout & Sizing</div>
          <div class="zyrox-setting-card">
            <label>UI Scale</label>
            <input type="range" class="set-scale" min="80" max="130" value="100" />
          </div>
          <div class="zyrox-setting-card">
            <label>Corner Radius</label>
            <input type="range" class="set-radius" min="6" max="20" value="14" />
          </div>
          <div class="zyrox-setting-card">
            <label>Panel Blur</label>
            <input type="range" class="set-blur" min="0" max="16" value="10" />
          </div>
          <div class="zyrox-subheading">Motion</div>
          <div class="zyrox-setting-card">
            <label>Module Hover Shift</label>
            <input type="range" class="set-hover-shift" min="0" max="6" value="2" />
          </div>
          <div class="zyrox-subheading">Main Window</div>
              <div class="zyrox-setting-card">
                <label>Accent Color</label>
                <input type="color" class="set-accent" value="#ff3d3d" />
              </div>
              <div class="zyrox-setting-card">
                <label>Background Gradient</label>
                <span class="zyrox-gradient-pair">
                  <input type="color" class="set-shell-bg-start" value="#ff3d3d" />
                  <input type="color" class="set-shell-bg-end" value="#000000" />
                </span>
              </div>
              <div class="zyrox-setting-card">
                <label>Top Bar Color</label>
                <input type="color" class="set-topbar-color" value="#ff4a4a" />
              </div>
              <div class="zyrox-setting-card">
                <label>Text Color</label>
                <input type="color" class="set-text" value="#d6d6df" />
              </div>
              <div class="zyrox-setting-card">
                <label>Panel Border</label>
                <input type="color" class="set-border" value="#ff6f6f" />
              </div>
              <div class="zyrox-setting-card">
                <label>Background Opacity</label>
                <input type="range" class="set-opacity" min="20" max="100" value="45" />
              </div>
          <div class="zyrox-subheading">Buttons & Inputs</div>
              <div class="zyrox-setting-card">
                <label>Outline Color</label>
                <input type="color" class="set-outline-color" value="#ff5b5b" />
              </div>
              <div class="zyrox-setting-card">
                <label>Slider Color</label>
                <input type="color" class="set-slider-color" value="#ff6b6b" />
              </div>
              <div class="zyrox-setting-card">
                <label>Checkmark Color</label>
                <input type="color" class="set-checkmark-color" value="#ff6b6b" />
              </div>
              <div class="zyrox-setting-card">
                <label>Dropdown Background</label>
                <input type="color" class="set-select-bg" value="#17171f" />
              </div>
              <div class="zyrox-setting-card">
                <label>Dropdown Text</label>
                <input type="color" class="set-select-text" value="#ffe5e5" />
              </div>
              <div class="zyrox-setting-card">
                <label>Text Input Background</label>
                <input type="color" class="set-input-bg" value="#17171f" />
              </div>
              <div class="zyrox-setting-card">
                <label>Text Input Text</label>
                <input type="color" class="set-input-text" value="#ffe5e5" />
              </div>
          <div class="zyrox-subheading">Typography</div>
              <div class="zyrox-setting-card">
                <label>Font Family</label>
                <select class="set-font">
                  <option value="Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif" selected>Inter (Default)</option>
                  <option value="JetBrains Mono, 'Courier New', monospace">JetBrains Mono</option>
                  <option value="'Segoe UI', Tahoma, Geneva, Verdana, sans-serif">Segoe UI</option>
                  <option value="Roboto, 'Helvetica Neue', Arial, sans-serif">Roboto</option>
                  <option value="'Open Sans', 'Helvetica Neue', Arial, sans-serif">Open Sans</option>
                  <option value="'Fira Code', 'Courier New', monospace">Fira Code</option>
                  <option value="Poppins, 'Helvetica Neue', Arial, sans-serif">Poppins</option>
                </select>
              </div>
              <div class="zyrox-setting-card">
                <label>Muted Text</label>
                <input type="color" class="set-muted-text" value="#9b9bab" />
              </div>
              <div class="zyrox-setting-card">
                <label>Label Accent</label>
                <input type="color" class="set-accent-soft" value="#ffbdbd" />
              </div>
              <div class="zyrox-setting-card">
                <label>Search Text</label>
                <input type="color" class="set-search-text" value="#ffe6e6" />
              </div>
          <div class="zyrox-subheading">Icons & Badges</div>
              <div class="zyrox-setting-card">
                <label>Icon Color</label>
                <input type="color" class="set-icon-color" value="#ffdada" />
              </div>
              <div class="zyrox-setting-card">
                <label>Panel Count Text</label>
                <input type="color" class="set-panel-count-text" value="#ffd9d9" />
              </div>
              <div class="zyrox-setting-card">
                <label>Panel Count Border</label>
                <input type="color" class="set-panel-count-border" value="#ff6464" />
              </div>
              <div class="zyrox-setting-card">
                <label>Panel Count Background</label>
                <input type="color" class="set-panel-count-bg" value="#1a1a1e" />
              </div>
          <div class="zyrox-subheading">Panels & Modules</div>
              <div class="zyrox-setting-card">
                <label>Module Bar Gradient</label>
                <span class="zyrox-gradient-pair">
                  <input type="color" class="set-header-start" value="#ff4a4a" />
                  <input type="color" class="set-header-end" value="#3c1212" />
                </span>
              </div>
              <div class="zyrox-setting-card">
                <label>Module Bar Text</label>
                <input type="color" class="set-header-text" value="#ffffff" />
              </div>
          <div class="zyrox-subheading">Settings Menu</div>
              <div class="zyrox-setting-card">
                <label>Settings Header Gradient</label>
                <span class="zyrox-gradient-pair">
                  <input type="color" class="set-settings-header-start" value="#ff3d3d" />
                  <input type="color" class="set-settings-header-end" value="#2d0c0c" />
                </span>
              </div>
              <div class="zyrox-setting-card">
                <label>Settings Sidebar Tint</label>
                <input type="color" class="set-settings-sidebar" value="#181820" />
              </div>
              <div class="zyrox-setting-card">
                <label>Settings Body Tint</label>
                <input type="color" class="set-settings-body" value="#121216" />
              </div>
              <div class="zyrox-setting-card">
                <label>Settings Text Color</label>
                <input type="color" class="set-settings-text" value="#ffe5e5" />
              </div>
              <div class="zyrox-setting-card">
                <label>Settings Subtext Color</label>
                <input type="color" class="set-settings-subtext" value="#c2c2ce" />
              </div>
              <div class="zyrox-setting-card">
                <label>Settings Card Border</label>
                <input type="color" class="set-settings-card-border" value="#ffffff" />
              </div>
              <div class="zyrox-setting-card">
                <label>Settings Card Background</label>
                <input type="color" class="set-settings-card-bg" value="#ffffff" />
              </div>
              <div class="zyrox-setting-card">
                <label>ESP Value Text Color</label>
                <input type="color" class="set-esp-value-text-color" value="#ffffff" />
              </div>
        </div>
      </div>
      <div class="zyrox-settings-pane hidden" data-pane="about">
        <div class="zyrox-settings-body">
          <div class="zyrox-subheading">Client Info</div>
          <div class="zyrox-setting-card">
            <div class="zyrox-about-content">
              <div><b>TEDDY Client</b> is a custom opensource userscript hacked client for Gimkit with module toggles, keybinds, and theming controls.</div>
              <div>We are not responsible for any bans, account issues, data loss, or damages that may result from using this client. Use it at your own risk.</div>
              <div>Version: ${CONFIG.version}</div>
              <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <a
                  class="zyrox-btn zyrox-about-source-btn"
                  href="https://github.com/Zyrox-client/Zyrox-gimkit-client"
                  target="_blank"
                  rel="noopener noreferrer"
                >View Source Code</a>
                <a
                  class="zyrox-btn zyrox-about-source-btn"
                  href="https://coindrop.to/zyrox-client"
                  target="_blank"
                  rel="noopener noreferrer"
                >Support Us</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
      <div class="zyrox-settings-actions">
      <div class="zyrox-settings-actions-group" style="flex-direction:column;gap:5px;align-items:flex-start;">
        <button class="zyrox-btn zyrox-settings-action-btn settings-reset-positions" type="button">Reset Positions</button>
        <button class="zyrox-btn zyrox-settings-action-btn settings-reset" type="button">Reset Appearance</button>
        <button class="zyrox-btn zyrox-settings-action-btn settings-reset-all" type="button" style="opacity:0.8;">Reset All</button>
      </div>
      <div class="zyrox-settings-actions-group">
        <button class="zyrox-btn settings-save" type="button">Save</button>
        <button class="zyrox-btn settings-close" type="button">Close</button>
      </div>
    </div>
  `;
        configBackdrop.appendChild(settingsMenu);

        function absorbMenuInputEvents(node) {
            if (!node) return;
            const block = (event) => {
                event.stopPropagation();
            };
            ["pointerdown", "mousedown", "click", "dblclick", "contextmenu"].forEach((type) => {
                node.addEventListener(type, block, false);
            });
        }
        absorbMenuInputEvents(root);
        absorbMenuInputEvents(configBackdrop);
        absorbMenuInputEvents(configMenu);
        absorbMenuInputEvents(settingsMenu);

        const configTitleEl = configMenu.querySelector(".zyrox-config-title");
        const configSubEl = configMenu.querySelector(".zyrox-config-sub");
        const configCloseBtn = configMenu.querySelector(".config-close-btn");
        const settingsTabs = [...settingsMenu.querySelectorAll(".zyrox-settings-tab")];
        const settingsPanes = [...settingsMenu.querySelectorAll(".zyrox-settings-pane")];
        const configBody = configMenu.querySelector(".zyrox-config-body");
        // Backward-compat alias for legacy code paths that still reference this identifier.
        const setBindButtonEl = configMenu.querySelector(".set-bind-btn");
        const settingsMenuKeyBtn = settingsMenu.querySelector(".settings-menu-key");
        const settingsMenuKeyResetBtn = settingsMenu.querySelector(".settings-menu-key-reset");
        const settingsTopCloseBtn = settingsMenu.querySelector(".settings-close-top");
        const settingsSaveBtn = settingsMenu.querySelector(".settings-save");
        const presetButtons = [...settingsMenu.querySelectorAll(".zyrox-preset-btn")];
        const searchAutofocusInput = settingsMenu.querySelector(".set-search-autofocus");
        const hiddenCategoriesList = settingsMenu.querySelector(".zyrox-hidden-categories-list");
        const accentInput = settingsMenu.querySelector(".set-accent");
        const shellBgStartInput = settingsMenu.querySelector(".set-shell-bg-start");
        const shellBgEndInput = settingsMenu.querySelector(".set-shell-bg-end");
        const topbarColorInput = settingsMenu.querySelector(".set-topbar-color");
        const iconColorInput = settingsMenu.querySelector(".set-icon-color");
        const outlineColorInput = settingsMenu.querySelector(".set-outline-color");
        const panelCountTextInput = settingsMenu.querySelector(".set-panel-count-text");
        const panelCountBorderInput = settingsMenu.querySelector(".set-panel-count-border");
        const panelCountBgInput = settingsMenu.querySelector(".set-panel-count-bg");
        const borderInput = settingsMenu.querySelector(".set-border");
        const textInput = settingsMenu.querySelector(".set-text");
        const opacityInput = settingsMenu.querySelector(".set-opacity");
        const sliderColorInput = settingsMenu.querySelector(".set-slider-color");
        const checkmarkColorInput = settingsMenu.querySelector(".set-checkmark-color");
        const selectBgInput = settingsMenu.querySelector(".set-select-bg");
        const selectTextInput = settingsMenu.querySelector(".set-select-text");
        const inputBgInput = settingsMenu.querySelector(".set-input-bg");
        const inputTextInput = settingsMenu.querySelector(".set-input-text");
        const mutedTextInput = settingsMenu.querySelector(".set-muted-text");
        const accentSoftInput = settingsMenu.querySelector(".set-accent-soft");
        const searchTextInput = settingsMenu.querySelector(".set-search-text");
        const fontInput = settingsMenu.querySelector(".set-font");
        const headerStartInput = settingsMenu.querySelector(".set-header-start");
        const headerEndInput = settingsMenu.querySelector(".set-header-end");
        const headerTextInput = settingsMenu.querySelector(".set-header-text");
        const settingsHeaderStartInput = settingsMenu.querySelector(".set-settings-header-start");
        const settingsHeaderEndInput = settingsMenu.querySelector(".set-settings-header-end");
        const settingsSidebarInput = settingsMenu.querySelector(".set-settings-sidebar");
        const settingsBodyInput = settingsMenu.querySelector(".set-settings-body");
        const settingsTextInput = settingsMenu.querySelector(".set-settings-text");
        const settingsSubtextInput = settingsMenu.querySelector(".set-settings-subtext");
        const settingsCardBorderInput = settingsMenu.querySelector(".set-settings-card-border");
        const settingsCardBgInput = settingsMenu.querySelector(".set-settings-card-bg");
        const espValueTextColorInput = settingsMenu.querySelector(".set-esp-value-text-color");
        const scaleInput = settingsMenu.querySelector(".set-scale");
        const radiusInput = settingsMenu.querySelector(".set-radius");
        const blurInput = settingsMenu.querySelector(".set-blur");
        const hoverShiftInput = settingsMenu.querySelector(".set-hover-shift");
        const displayModeButtons = [...settingsMenu.querySelectorAll(".set-display-mode")];
        const settingsResetPositionsBtn = settingsMenu.querySelector(".settings-reset-positions");
        const settingsResetBtn = settingsMenu.querySelector(".settings-reset");
        const settingsResetAllBtn = settingsMenu.querySelector(".settings-reset-all");
        const settingsCloseBtn = settingsMenu.querySelector(".settings-close");
        const panelByName = new Map();
        const configResetBtn = configMenu.querySelector(".config-reset-btn");
        const panelCollapseButtons = new Map();
        let openConfigModule = null;
        let currentSetBindBtn = null;
        let currentResetBindBtn = null;
        let currentBindTextEl = null;

        function setBindButtonText(text) {
            const bindButton = currentSetBindBtn || setBindButtonEl || configMenu.querySelector(".set-bind-btn");
            if (bindButton) bindButton.textContent = text;
        }

        function setFooterText() {
            footer.innerHTML = DEFAULT_FOOTER_HTML();
        }

        function setCurrentBindText(bind) {
            if (!currentBindTextEl) return;
            currentBindTextEl.textContent = bind ? `Keybind: ${bind}` : "Keybind: none";
        }

        function getModuleLayoutConfig(moduleName) {
            const allGroups = [...MENU_LAYOUT.general.groups, ...MENU_LAYOUT.gamemodeSpecific.groups];
            const found = allGroups
                .flatMap((group) => group.modules || [])
                .find((mod) => typeof mod === "object" && mod && mod.name === moduleName);
            return found || null;
        }

        function getModuleDescription(moduleName) {
            const layout = getModuleLayoutConfig(moduleName);
            if (layout?.description) return layout.description;
            return MODULE_DESCRIPTIONS[moduleName] || "Configure this module.";
        }

        function ensureModuleConfigStore() {
            if (state.moduleConfig instanceof Map) return state.moduleConfig;

            const recovered = new Map();
            if (state.moduleConfig && typeof state.moduleConfig === "object") {
                for (const [moduleName, cfg] of Object.entries(state.moduleConfig)) {
                    if (cfg && typeof cfg === "object") {
                        recovered.set(moduleName, { ...cfg, keybind: cfg.keybind || null });
                    }
                }
            }
            state.moduleConfig = recovered;
            return state.moduleConfig;
        }

        function moduleCfg(name) {
            const store = ensureModuleConfigStore();
            const layout = getModuleLayoutConfig(name);
            if (!store.has(name)) {
                const settings = {};
                if (layout && Array.isArray(layout.settings)) {
                    for (const setting of layout.settings) {
                        settings[setting.id] = setting.default ?? setting.min ?? 0;
                    }
                }
                store.set(name, { keybind: null, ...settings });
            }
            const cfg = store.get(name);
            if (cfg && layout && Array.isArray(layout.settings)) {
                for (const setting of layout.settings) {
                    if (cfg[setting.id] !== undefined) continue;
                    cfg[setting.id] = setting.default ?? setting.min ?? 0;
                }
            }
            if (name === "ESP") {
                window.__zyroxEspConfig = { ...getEspRenderConfig(), ...cfg };
            } else if (name === "Triggerbot (Autoshoot)") {
                window.__zyroxTriggerAssistConfig = { ...getTriggerAssistConfig(), ...cfg };
            } else if (name === "Aimbot") {
                window.__zyroxAutoAimConfig = { ...getAutoAimConfig(), ...cfg };
            } else if (name === "Auto Answer") {
                window.__zyroxAutoAnswerConfig = { ...cfg };
            }
            return cfg;
        }


        function setBindLabel(item, moduleName) {
            const label = item.querySelector(".zyrox-bind-label");
            const bind = moduleCfg(moduleName).keybind;
            label.textContent = bind || "";
            label.style.display = bind ? "" : "none";
        }

        function toggleModule(moduleName) {
            const item = state.moduleItems.get(moduleName);
            const moduleInstance = state.modules.get(moduleName);
            if (!item || !moduleInstance) return;

            if (moduleInstance.enabled) {
                moduleInstance.disable();
                item.classList.remove("active");
                state.enabledModules.delete(moduleName);
                if (moduleName === "Auto Answer") stopAutoAnswer();
            } else {
                moduleInstance.enable();
                item.classList.add("active");
                state.enabledModules.add(moduleName);
                if (moduleName === "Auto Answer") startAutoAnswer();
            }
            saveSettings();
        }

        // ---------------------------------------------------------------------------
        // AUTO-ANSWER MODULE CONTROLS
        // The actual logic runs in page context (injected above).
        // These functions just start/stop the interval via window.__zyroxAutoAnswer.
        // ---------------------------------------------------------------------------
        function stopAutoAnswer() {
            window.__zyroxAutoAnswer?.stop();
        }

        function startAutoAnswer() {
            const cfg = moduleCfg("Auto Answer");
            const speed = Math.max(200, Number(cfg.speed) || 1000);
            const triviaDelayNumber = Number(cfg.triviaDelay);
            const triviaDelay = Math.max(0, Math.min(8000, Number.isFinite(triviaDelayNumber) ? triviaDelayNumber : 1500));
            window.__zyroxAutoAnswer?.start(speed, { pardyDelay: triviaDelay });
        }

        function refreshAutoAnswerLoopIfEnabled() {
            if (state.enabledModules.has("Auto Answer")) startAutoAnswer();
        }

        function getAnswerPopupConfig() {
            const cfg = moduleCfg("Answer Popup");
            return {
                title: String(cfg.title ?? "Draw It Answer"),
                prefix: String(cfg.prefix ?? "Answer:"),
                durationMs: Math.max(400, Number(cfg.durationMs) || 2600),
                background: String(cfg.background ?? "#121525"),
                accent: String(cfg.accent ?? "#00e5ff"),
                textColor: String(cfg.textColor ?? "#ffffff"),
            };
        }

        function ensureAnswerPopupContainer() {
            if (answerPopupState.container?.isConnected) return answerPopupState.container;
            const popup = document.createElement("div");
            popup.className = "zyrox-answer-popup";
            popup.style.cssText = [
                "position:fixed",
                "left:50%",
                "top:92px",
                "transform:translate(-50%, -18px)",
                "min-width:260px",
                "max-width:min(86vw,640px)",
                "padding:12px 14px",
                "border-radius:12px",
                "font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif",
                "z-index:2147483647",
                "opacity:0",
                "pointer-events:none",
                "transition:opacity .18s ease, transform .18s ease",
                "box-shadow:0 14px 34px rgba(0,0,0,.45)",
                "border:1px solid rgba(255,255,255,.14)",
                "display:none",
                "white-space:normal",
                "overflow-wrap:anywhere",
            ].join(";");
            document.documentElement.appendChild(popup);
            answerPopupState.container = popup;
            return popup;
        }

        function showAnswerPopup(answerText) {
            if (!answerPopupState.enabled) return;
            const answer = String(answerText || "").trim();
            if (!answer) return;
            const now = Date.now();
            if (answer === answerPopupState.lastAnswer && now - answerPopupState.lastShownAt < 700) return;
            answerPopupState.lastAnswer = answer;
            answerPopupState.lastShownAt = now;

            const popup = ensureAnswerPopupContainer();
            const cfg = getAnswerPopupConfig();
            popup.style.background = cfg.background;
            popup.style.color = cfg.textColor;
            popup.style.borderLeft = `4px solid ${cfg.accent}`;
            popup.innerHTML = `
      <div style="font-size:12px;letter-spacing:.04em;text-transform:uppercase;opacity:.75;margin-bottom:4px;">${cfg.title}</div>
      <div style="font-size:16px;font-weight:700;line-height:1.25;">${cfg.prefix} <span style="color:${cfg.accent};">${answer}</span></div>
    `;

            popup.style.display = "block";
            popup.style.opacity = "1";
            popup.style.transform = "translate(-50%, 0)";
            if (answerPopupState.timeoutId) clearTimeout(answerPopupState.timeoutId);
            answerPopupState.timeoutId = setTimeout(() => {
                popup.style.opacity = "0";
                popup.style.transform = "translate(-50%, -18px)";
                setTimeout(() => {
                    if (popup.style.opacity === "0") popup.style.display = "none";
                }, 180);
            }, cfg.durationMs);
        }


        function resetModuleConfig(moduleName) {
            if (!moduleName) return;
            const store = ensureModuleConfigStore();
            store.delete(moduleName);
            const freshCfg = moduleCfg(moduleName);
            const module = state.modules.get(moduleName);
            const behavior = MODULE_BEHAVIORS[moduleName];
            if (module?.enabled) {
                try { behavior?.onDisable?.(); } catch (error) { console.error(`[Zyrox] ${moduleName} failed to disable during config reset`, error); }
                try { behavior?.onEnable?.(); } catch (error) { console.error(`[Zyrox] ${moduleName} failed to re-enable during config reset`, error); }
            }
            const item = state.moduleItems.get(moduleName);
            if (item) setBindLabel(item, moduleName);
            setCurrentBindText(freshCfg.keybind || null);
            state.listeningForBind = null;
            setBindButtonText("Set keybind");
            saveSettings();
        }

        function closeConfig() {
            configBackdrop.classList.add("hidden");
            configMenu.classList.add("hidden");
            settingsMenu.classList.add("hidden");
            openConfigModule = null;
            currentBindTextEl = null;
            state.listeningForBind = null;
            setBindButtonText("Set keybind");
        }

        function openConfig(moduleName) {
            openConfigModule = moduleName;
            const cfg = moduleCfg(moduleName);
            const moduleLayout = getModuleLayoutConfig(moduleName);

            configBody.innerHTML = `
      <div class="zyrox-config-row">
        <span class="zyrox-keybind-current">Keybind: ${cfg.keybind || "none"}</span>
        <div class="zyrox-config-actions">
          <button class="zyrox-btn zyrox-btn-square reset-bind-btn" type="button" title="Reset keybind">↺</button>
          <button class="zyrox-btn set-bind-btn" type="button">Set keybind</button>
        </div>
      </div>
    `;

            currentResetBindBtn = configMenu.querySelector(".reset-bind-btn");
            currentSetBindBtn = configMenu.querySelector(".set-bind-btn");
            currentBindTextEl = configMenu.querySelector(".zyrox-keybind-current");

            if (currentSetBindBtn) {
                currentSetBindBtn.addEventListener("click", () => {
                    if (!openConfigModule) return;
                    state.listeningForBind = openConfigModule;
                    setBindButtonText("Press any key...");
                });
            }

            if (currentResetBindBtn) {
                currentResetBindBtn.addEventListener("click", () => {
                    if (!openConfigModule) return;
                    const activeCfg = moduleCfg(openConfigModule);
                    activeCfg.keybind = null;
                    const item = state.moduleItems.get(openConfigModule);
                    if (item) setBindLabel(item, openConfigModule);
                    setCurrentBindText(null);
                    state.listeningForBind = null;
                    setBindButtonText("Set keybind");
                    saveSettings();
                });
            }

            if (moduleName === "ESP") {
                const defaults = getEspRenderConfig();
                Object.assign(cfg, { ...defaults, ...cfg });
                window.__zyroxEspConfig = { ...cfg };

                const tabButtons = document.createElement("div");
                tabButtons.style.display = "flex";
                tabButtons.style.gap = "8px";
                tabButtons.style.marginBottom = "8px";
                const enemiesTabBtn = document.createElement("button");
                enemiesTabBtn.className = "zyrox-btn";
                enemiesTabBtn.type = "button";
                enemiesTabBtn.textContent = "Enemies";
                const teammatesTabBtn = document.createElement("button");
                teammatesTabBtn.className = "zyrox-btn";
                teammatesTabBtn.type = "button";
                teammatesTabBtn.textContent = "Teammates";
                tabButtons.append(enemiesTabBtn, teammatesTabBtn);
                configBody.appendChild(tabButtons);

                const enemiesPane = document.createElement("div");
                enemiesPane.style.display = "flex";
                enemiesPane.style.flexDirection = "column";
                enemiesPane.style.gap = "8px";
                const teammatesPane = document.createElement("div");
                teammatesPane.style.display = "none";
                teammatesPane.style.flexDirection = "column";
                teammatesPane.style.gap = "8px";
                configBody.append(enemiesPane, teammatesPane);

                const setEspTab = (tab) => {
                    const isEnemies = tab !== "teammates";
                    enemiesPane.style.display = isEnemies ? "flex" : "none";
                    teammatesPane.style.display = isEnemies ? "none" : "flex";
                    enemiesTabBtn.style.opacity = isEnemies ? "1" : "0.65";
                    teammatesTabBtn.style.opacity = isEnemies ? "0.65" : "1";
                };
                enemiesTabBtn.addEventListener("click", () => setEspTab("enemies"));
                teammatesTabBtn.addEventListener("click", () => setEspTab("teammates"));
                setEspTab("enemies");

                const makeRow = (container, title, html) => {
                    const row = document.createElement("div");
                    row.className = "zyrox-setting-card";
                    row.innerHTML = `
          <div style="display:flex;flex-direction:column;gap:8px;width:100%;">
            <label style="font-weight:600;">${title}</label>
            ${html}
          </div>
        `;
                    container.appendChild(row);
                    return row;
                };

                const enemyFilterRow = makeRow(enemiesPane, "Enemy Visibility", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" class="esp-show-enemies" ${cfg.showEnemies !== false ? "checked" : ""} />
            Show enemies
          </label>
        </div>
      `);

                const hitboxRow = makeRow(enemiesPane, "Hitbox", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-hitbox-enabled" ${cfg.hitbox ? "checked" : ""} /> Enabled</label>
          <label>Size <input type="range" class="esp-hitbox-size" min="24" max="270" step="2" value="${cfg.hitboxSize}" /></label>
          <span class="esp-hitbox-size-value esp-value-text">${cfg.hitboxSize}px</span>
          <label>Width <input type="range" class="esp-hitbox-width" min="1" max="10" step="1" value="${cfg.hitboxWidth}" /></label>
          <span class="esp-hitbox-width-value esp-value-text">${cfg.hitboxWidth}px</span>
          <input type="color" class="esp-hitbox-color" value="${cfg.hitboxColor}" />
        </div>
      `);

                const namesRow = makeRow(enemiesPane, "Names", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-name-show-name" ${resolveNameDistanceVisibility(cfg, false).showName ? "checked" : ""} /> Name</label>
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-name-show-distance" ${resolveNameDistanceVisibility(cfg, false).showDistance ? "checked" : ""} /> Distance</label>
          <label>Size <input type="range" class="esp-name-size" min="10" max="32" step="1" value="${cfg.nameSize}" /></label>
          <span class="esp-name-size-value esp-value-text">${cfg.nameSize}px</span>
          <input type="color" class="esp-name-color" value="${cfg.nameColor}" />
          <label>Distance Style
            <select class="esp-name-distance-style">
              <option value="dot" ${cfg.nameDistanceStyle === "dot" ? "selected" : ""}>Name • 120m</option>
              <option value="dash" ${cfg.nameDistanceStyle === "dash" ? "selected" : ""}>Name - 120m</option>
              <option value="pipe" ${cfg.nameDistanceStyle === "pipe" ? "selected" : ""}>Name | 120m</option>
              <option value="paren" ${cfg.nameDistanceStyle === "paren" ? "selected" : ""}>Name (120m)</option>
              <option value="distanceFirst" ${cfg.nameDistanceStyle === "distanceFirst" ? "selected" : ""}>120m • Name</option>
            </select>
          </label>
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-name-outline-enabled" ${cfg.nameOutline !== false ? "checked" : ""} /> Outline</label>
          <label>Outline Width <input type="range" class="esp-name-outline-width" min="1" max="6" step="1" value="${cfg.nameOutlineWidth}" /></label>
          <span class="esp-name-outline-width-value esp-value-text">${cfg.nameOutlineWidth}px</span>
          <input type="color" class="esp-name-outline-color" value="${cfg.nameOutlineColor || "#000000"}" />
        </div>
      `);

                const offscreenRow = makeRow(enemiesPane, "Off-screen", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label>Mode
            <select class="esp-offscreen-style">
              <option value="none" ${cfg.offscreenStyle === "none" ? "selected" : ""}>None</option>
              <option value="tracers" ${cfg.offscreenStyle === "tracers" ? "selected" : ""}>Tracers</option>
              <option value="arrows" ${cfg.offscreenStyle === "arrows" ? "selected" : ""}>Arrows</option>
            </select>
          </label>
          <label style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" class="esp-always-tracer" ${cfg.alwaysTracer ? "checked" : ""} />
            Always Show Tracer
          </label>
          <label>Theme
            <select class="esp-offscreen-theme">
              <option value="classic" ${cfg.offscreenTheme === "classic" ? "selected" : ""}>Classic</option>
              <option value="dashed" ${cfg.offscreenTheme === "dashed" ? "selected" : ""}>Dashed</option>
              <option value="neon" ${cfg.offscreenTheme === "neon" ? "selected" : ""}>Neon</option>
            </select>
          </label>
          <span class="esp-tracer-controls" style="display:flex;align-items:center;gap:10px;">
            <label>Tracer Width <input type="range" class="esp-tracer-width" min="1" max="8" step="1" value="${cfg.tracerWidth}" /></label>
            <span class="esp-tracer-width-value esp-value-text">${cfg.tracerWidth}px</span>
            <input type="color" class="esp-tracer-color" value="${cfg.tracerColor}" />
          </span>
          <span class="esp-arrow-controls" style="display:flex;align-items:center;gap:10px;">
            <label>Arrow Size <input type="range" class="esp-arrow-size" min="8" max="30" step="1" value="${cfg.arrowSize}" /></label>
            <span class="esp-arrow-size-value esp-value-text">${cfg.arrowSize}px</span>
            <input type="color" class="esp-arrow-color" value="${cfg.arrowColor}" />
            <label>Arrow Style
              <select class="esp-arrow-style">
                <option value="regular" ${cfg.arrowStyle === "regular" ? "selected" : ""}>Regular Arrow</option>
                <option value="dot" ${cfg.arrowStyle === "dot" ? "selected" : ""}>Dot</option>
                <option value="modern" ${cfg.arrowStyle === "modern" ? "selected" : ""}>Modern Arrow</option>
              </select>
            </label>
          </span>
        </div>
      `);

                const teammateFilterRow = makeRow(teammatesPane, "Teammate Visibility", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" class="esp-show-teammates" ${cfg.showTeammates !== false ? "checked" : ""} />
            Show teammates
          </label>
        </div>
      `);

                const teammateHitboxRow = makeRow(teammatesPane, "Hitbox", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-teammate-hitbox-enabled" ${cfg.teammateHitbox ? "checked" : ""} /> Enabled</label>
          <label>Size <input type="range" class="esp-teammate-hitbox-size" min="24" max="270" step="2" value="${cfg.teammateHitboxSize}" /></label>
          <span class="esp-teammate-hitbox-size-value esp-value-text">${cfg.teammateHitboxSize}px</span>
          <label>Width <input type="range" class="esp-teammate-hitbox-width" min="1" max="10" step="1" value="${cfg.teammateHitboxWidth}" /></label>
          <span class="esp-teammate-hitbox-width-value esp-value-text">${cfg.teammateHitboxWidth}px</span>
          <input type="color" class="esp-teammate-hitbox-color" value="${cfg.teammateHitboxColor || "#36d17c"}" />
        </div>
      `);

                const teammateNamesRow = makeRow(teammatesPane, "Names", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-teammate-name-show-name" ${resolveNameDistanceVisibility(cfg, true).showName ? "checked" : ""} /> Name</label>
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-teammate-name-show-distance" ${resolveNameDistanceVisibility(cfg, true).showDistance ? "checked" : ""} /> Distance</label>
          <label>Size <input type="range" class="esp-teammate-name-size" min="10" max="32" step="1" value="${cfg.teammateNameSize}" /></label>
          <span class="esp-teammate-name-size-value esp-value-text">${cfg.teammateNameSize}px</span>
          <input type="color" class="esp-teammate-name-color" value="${cfg.teammateNameColor || "#baf7d2"}" />
          <label>Distance Style
            <select class="esp-teammate-name-distance-style">
              <option value="dot" ${cfg.teammateNameDistanceStyle === "dot" ? "selected" : ""}>Name • 120m</option>
              <option value="dash" ${cfg.teammateNameDistanceStyle === "dash" ? "selected" : ""}>Name - 120m</option>
              <option value="pipe" ${cfg.teammateNameDistanceStyle === "pipe" ? "selected" : ""}>Name | 120m</option>
              <option value="paren" ${cfg.teammateNameDistanceStyle === "paren" ? "selected" : ""}>Name (120m)</option>
              <option value="distanceFirst" ${cfg.teammateNameDistanceStyle === "distanceFirst" ? "selected" : ""}>120m • Name</option>
            </select>
          </label>
          <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" class="esp-teammate-name-outline-enabled" ${cfg.teammateNameOutline !== false ? "checked" : ""} /> Outline</label>
          <label>Outline Width <input type="range" class="esp-teammate-name-outline-width" min="1" max="6" step="1" value="${cfg.teammateNameOutlineWidth}" /></label>
          <span class="esp-teammate-name-outline-width-value esp-value-text">${cfg.teammateNameOutlineWidth}px</span>
          <input type="color" class="esp-teammate-name-outline-color" value="${cfg.teammateNameOutlineColor || "#ffffff"}" />
        </div>
      `);

                const teammateOffscreenRow = makeRow(teammatesPane, "Off-screen", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label>Mode
            <select class="esp-teammate-offscreen-style">
              <option value="none" ${cfg.teammateOffscreenStyle === "none" ? "selected" : ""}>None</option>
              <option value="tracers" ${cfg.teammateOffscreenStyle === "tracers" ? "selected" : ""}>Tracers</option>
              <option value="arrows" ${cfg.teammateOffscreenStyle === "arrows" ? "selected" : ""}>Arrows</option>
            </select>
          </label>
          <label style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" class="esp-teammate-always-tracer" ${cfg.teammateAlwaysTracer ? "checked" : ""} />
            Always Show Tracer
          </label>
          <label>Theme
            <select class="esp-teammate-offscreen-theme">
              <option value="classic" ${cfg.teammateOffscreenTheme === "classic" ? "selected" : ""}>Classic</option>
              <option value="dashed" ${cfg.teammateOffscreenTheme === "dashed" ? "selected" : ""}>Dashed</option>
              <option value="neon" ${cfg.teammateOffscreenTheme === "neon" ? "selected" : ""}>Neon</option>
            </select>
          </label>
          <span class="esp-teammate-tracer-controls" style="display:flex;align-items:center;gap:10px;">
            <label>Tracer Width <input type="range" class="esp-teammate-tracer-width" min="1" max="8" step="1" value="${cfg.teammateTracerWidth}" /></label>
            <span class="esp-teammate-tracer-width-value esp-value-text">${cfg.teammateTracerWidth}px</span>
            <input type="color" class="esp-teammate-tracer-color" value="${cfg.teammateTracerColor || "#36d17c"}" />
          </span>
          <span class="esp-teammate-arrow-controls" style="display:flex;align-items:center;gap:10px;">
            <label>Arrow Size <input type="range" class="esp-teammate-arrow-size" min="8" max="30" step="1" value="${cfg.teammateArrowSize}" /></label>
            <span class="esp-teammate-arrow-size-value esp-value-text">${cfg.teammateArrowSize}px</span>
            <input type="color" class="esp-teammate-arrow-color" value="${cfg.teammateArrowColor || "#36d17c"}" />
            <label>Arrow Style
              <select class="esp-teammate-arrow-style">
                <option value="regular" ${cfg.teammateArrowStyle === "regular" ? "selected" : ""}>Regular Arrow</option>
                <option value="dot" ${cfg.teammateArrowStyle === "dot" ? "selected" : ""}>Dot</option>
                <option value="modern" ${cfg.teammateArrowStyle === "modern" ? "selected" : ""}>Modern Arrow</option>
              </select>
            </label>
          </span>
        </div>
      `);

                const syncEsp = () => {
                    window.__zyroxEspConfig = { ...cfg };
                    saveSettings();
                };
                syncEsp();
                const applyValueTextColor = () => {
                    for (const el of configBody.querySelectorAll(".esp-value-text")) {
                        el.style.color = cfg.valueTextColor || "#ffffff";
                    }
                };
                applyValueTextColor();

                const bindCheckbox = (root, selector, key) => {
                    const input = root.querySelector(selector);
                    if (!input) return;
                    input.addEventListener("change", (event) => {
                        cfg[key] = Boolean(event.target.checked);
                        syncEsp();
                    });
                };
                const bindColor = (root, selector, key) => {
                    const input = root.querySelector(selector);
                    if (!input) return;
                    input.addEventListener("input", (event) => {
                        cfg[key] = String(event.target.value || "#ffffff");
                        syncEsp();
                    });
                };
                const bindSlider = (root, selector, key, labelSelector) => {
                    const input = root.querySelector(selector);
                    const label = root.querySelector(labelSelector);
                    if (!input) return;
                    input.addEventListener("input", (event) => {
                        const value = Number(event.target.value);
                        cfg[key] = value;
                        if (label) label.textContent = `${value}px`;
                        syncEsp();
                    });
                };

                bindCheckbox(enemyFilterRow, ".esp-show-enemies", "showEnemies");
                bindCheckbox(hitboxRow, ".esp-hitbox-enabled", "hitbox");
                bindSlider(hitboxRow, ".esp-hitbox-size", "hitboxSize", ".esp-hitbox-size-value");
                bindSlider(hitboxRow, ".esp-hitbox-width", "hitboxWidth", ".esp-hitbox-width-value");
                bindColor(hitboxRow, ".esp-hitbox-color", "hitboxColor");

                bindCheckbox(namesRow, ".esp-name-show-name", "nameTextEnabled");
                bindCheckbox(namesRow, ".esp-name-show-distance", "distanceTextEnabled");
                bindSlider(namesRow, ".esp-name-size", "nameSize", ".esp-name-size-value");
                bindColor(namesRow, ".esp-name-color", "nameColor");
                bindCheckbox(namesRow, ".esp-name-outline-enabled", "nameOutline");
                bindSlider(namesRow, ".esp-name-outline-width", "nameOutlineWidth", ".esp-name-outline-width-value");
                bindColor(namesRow, ".esp-name-outline-color", "nameOutlineColor");
                const nameDistanceStyleInput = namesRow.querySelector(".esp-name-distance-style");
                if (nameDistanceStyleInput) {
                    nameDistanceStyleInput.addEventListener("change", (event) => {
                        cfg.nameDistanceStyle = String(event.target.value || "dot");
                        syncEsp();
                    });
                }

                const styleInput = offscreenRow.querySelector(".esp-offscreen-style");
                const tracerControls = offscreenRow.querySelector(".esp-tracer-controls");
                const arrowControls = offscreenRow.querySelector(".esp-arrow-controls");
                const alwaysTracerInput = offscreenRow.querySelector(".esp-always-tracer");
                const refreshIndicatorModeVisibility = () => {
                    const mode = cfg.offscreenStyle === "arrows" || cfg.offscreenStyle === "none" ? cfg.offscreenStyle : "tracers";
                    if (tracerControls) tracerControls.style.display = mode === "tracers" ? "flex" : "none";
                    if (arrowControls) arrowControls.style.display = mode === "arrows" ? "flex" : "none";
                };
                if (styleInput) {
                    styleInput.addEventListener("change", (event) => {
                        cfg.offscreenStyle = String(event.target.value || "tracers");
                        refreshIndicatorModeVisibility();
                        syncEsp();
                    });
                }
                const themeInput = offscreenRow.querySelector(".esp-offscreen-theme");
                if (themeInput) {
                    themeInput.addEventListener("change", (event) => {
                        cfg.offscreenTheme = String(event.target.value || "classic");
                        syncEsp();
                    });
                }
                if (alwaysTracerInput) {
                    alwaysTracerInput.addEventListener("change", (event) => {
                        cfg.alwaysTracer = Boolean(event.target.checked);
                        syncEsp();
                    });
                }
                bindSlider(offscreenRow, ".esp-tracer-width", "tracerWidth", ".esp-tracer-width-value");
                bindColor(offscreenRow, ".esp-tracer-color", "tracerColor");
                bindSlider(offscreenRow, ".esp-arrow-size", "arrowSize", ".esp-arrow-size-value");
                bindColor(offscreenRow, ".esp-arrow-color", "arrowColor");
                const arrowStyleInput = offscreenRow.querySelector(".esp-arrow-style");
                if (arrowStyleInput) {
                    arrowStyleInput.addEventListener("change", (event) => {
                        cfg.arrowStyle = String(event.target.value || "regular");
                        syncEsp();
                    });
                }
                bindCheckbox(teammateFilterRow, ".esp-show-teammates", "showTeammates");
                bindCheckbox(teammateHitboxRow, ".esp-teammate-hitbox-enabled", "teammateHitbox");
                bindSlider(teammateHitboxRow, ".esp-teammate-hitbox-size", "teammateHitboxSize", ".esp-teammate-hitbox-size-value");
                bindSlider(teammateHitboxRow, ".esp-teammate-hitbox-width", "teammateHitboxWidth", ".esp-teammate-hitbox-width-value");
                bindColor(teammateHitboxRow, ".esp-teammate-hitbox-color", "teammateHitboxColor");
                bindCheckbox(teammateNamesRow, ".esp-teammate-name-show-name", "teammateNameTextEnabled");
                bindCheckbox(teammateNamesRow, ".esp-teammate-name-show-distance", "teammateDistanceTextEnabled");
                bindSlider(teammateNamesRow, ".esp-teammate-name-size", "teammateNameSize", ".esp-teammate-name-size-value");
                bindColor(teammateNamesRow, ".esp-teammate-name-color", "teammateNameColor");
                bindCheckbox(teammateNamesRow, ".esp-teammate-name-outline-enabled", "teammateNameOutline");
                bindSlider(teammateNamesRow, ".esp-teammate-name-outline-width", "teammateNameOutlineWidth", ".esp-teammate-name-outline-width-value");
                bindColor(teammateNamesRow, ".esp-teammate-name-outline-color", "teammateNameOutlineColor");
                const teammateNameDistanceStyleInput = teammateNamesRow.querySelector(".esp-teammate-name-distance-style");
                if (teammateNameDistanceStyleInput) {
                    teammateNameDistanceStyleInput.addEventListener("change", (event) => {
                        cfg.teammateNameDistanceStyle = String(event.target.value || "dot");
                        syncEsp();
                    });
                }
                const teammateStyleInput = teammateOffscreenRow.querySelector(".esp-teammate-offscreen-style");
                const teammateTracerControls = teammateOffscreenRow.querySelector(".esp-teammate-tracer-controls");
                const teammateArrowControls = teammateOffscreenRow.querySelector(".esp-teammate-arrow-controls");
                const teammateAlwaysTracerInput = teammateOffscreenRow.querySelector(".esp-teammate-always-tracer");
                const refreshTeammateIndicatorModeVisibility = () => {
                    const mode = cfg.teammateOffscreenStyle === "arrows" || cfg.teammateOffscreenStyle === "none"
                        ? cfg.teammateOffscreenStyle
                        : "tracers";
                    if (teammateTracerControls) teammateTracerControls.style.display = mode === "tracers" ? "flex" : "none";
                    if (teammateArrowControls) teammateArrowControls.style.display = mode === "arrows" ? "flex" : "none";
                };
                if (teammateStyleInput) {
                    teammateStyleInput.addEventListener("change", (event) => {
                        cfg.teammateOffscreenStyle = String(event.target.value || "tracers");
                        refreshTeammateIndicatorModeVisibility();
                        syncEsp();
                    });
                }
                const teammateThemeInput = teammateOffscreenRow.querySelector(".esp-teammate-offscreen-theme");
                if (teammateThemeInput) {
                    teammateThemeInput.addEventListener("change", (event) => {
                        cfg.teammateOffscreenTheme = String(event.target.value || "classic");
                        syncEsp();
                    });
                }
                if (teammateAlwaysTracerInput) {
                    teammateAlwaysTracerInput.addEventListener("change", (event) => {
                        cfg.teammateAlwaysTracer = Boolean(event.target.checked);
                        syncEsp();
                    });
                }
                bindSlider(teammateOffscreenRow, ".esp-teammate-tracer-width", "teammateTracerWidth", ".esp-teammate-tracer-width-value");
                bindColor(teammateOffscreenRow, ".esp-teammate-tracer-color", "teammateTracerColor");
                bindSlider(teammateOffscreenRow, ".esp-teammate-arrow-size", "teammateArrowSize", ".esp-teammate-arrow-size-value");
                bindColor(teammateOffscreenRow, ".esp-teammate-arrow-color", "teammateArrowColor");
                const teammateArrowStyleInput = teammateOffscreenRow.querySelector(".esp-teammate-arrow-style");
                if (teammateArrowStyleInput) {
                    teammateArrowStyleInput.addEventListener("change", (event) => {
                        cfg.teammateArrowStyle = String(event.target.value || "regular");
                        syncEsp();
                    });
                }
                refreshIndicatorModeVisibility();
                refreshTeammateIndicatorModeVisibility();
            } else if (moduleName === "Crosshair") {
                const defaults = getCrosshairConfig();
                Object.assign(cfg, { ...defaults, ...cfg });
                window.__zyroxCrosshairConfig = { ...cfg };

                const syncCrosshair = () => { window.__zyroxCrosshairConfig = { ...cfg }; };
                syncCrosshair();

                const makeRow = (title, html) => {
                    const row = document.createElement("div");
                    row.className = "zyrox-setting-card";
                    row.innerHTML = `
          <div style="display:flex;flex-direction:column;gap:8px;width:100%;">
            <label style="font-weight:600;">${title}</label>
            ${html}
          </div>
        `;
                    configBody.appendChild(row);
                    return row;
                };

                const enabledRow = makeRow("Crosshair", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" class="xh-enabled" ${cfg.enabled !== false ? "checked" : ""} />
            Show Crosshair
          </label>
          <input type="color" class="xh-color" value="${cfg.color || "#ff3b3b"}" title="Crosshair color" />
        </div>
      `);

                const styleRow = makeRow("Style", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <select class="xh-style">
            <option value="cross"       ${cfg.style === "cross" ? "selected" : ""}>Cross (gap)</option>
            <option value="solid"       ${cfg.style === "solid" ? "selected" : ""}>Solid Cross</option>
            <option value="crossdot"    ${cfg.style === "crossdot" ? "selected" : ""}>Cross + Dot</option>
            <option value="dot"         ${cfg.style === "dot" ? "selected" : ""}>Dot</option>
            <option value="circle"      ${cfg.style === "circle" ? "selected" : ""}>Circle</option>
            <option value="circlecross" ${cfg.style === "circlecross" ? "selected" : ""}>Circle + Cross</option>
            <option value="plus"        ${cfg.style === "plus" ? "selected" : ""}>Plus (thick)</option>
            <option value="x"           ${cfg.style === "x" ? "selected" : ""}>X (diagonal)</option>
          </select>
        </div>
      `);

                const sizeRow = makeRow("Crosshair Size", `
        <div style="display:flex;align-items:center;gap:10px;">
          <input type="range" class="xh-crosshair-size" min="4" max="40" step="1" value="${cfg.crosshairSize ?? 25}" style="flex:1;" />
          <span class="xh-crosshair-size-label" style="min-width:36px;text-align:right;font-size:0.85em;opacity:0.75;">${cfg.crosshairSize ?? 25}px</span>
        </div>
      `);

                const lineSizeRow = makeRow("Cursor Width", `
        <div style="display:flex;align-items:center;gap:10px;">
          <input type="range" class="xh-line-size" min="0.5" max="6" step="0.5" value="${cfg.lineSize ?? 4}" style="flex:1;" />
          <span class="xh-line-size-label" style="min-width:36px;text-align:right;font-size:0.85em;opacity:0.75;">${cfg.lineSize ?? 4}px</span>
        </div>
      `);

                const lineRow = makeRow("Line to Cursor", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" class="xh-show-line" ${cfg.showLine ? "checked" : ""} />
            Show Line
          </label>
          <input type="color" class="xh-line-color" value="${cfg.lineColor || "#ff3b3b"}" title="Line color" />
        </div>
      `);

                const tracerSizeRow = makeRow("Tracer Thickness", `
        <div style="display:flex;align-items:center;gap:10px;">
          <input type="range" class="xh-tracer-size" min="0.5" max="5" step="0.5" value="${cfg.tracerLineSize ?? 1.5}" style="flex:1;" />
          <span class="xh-tracer-size-label" style="min-width:36px;text-align:right;font-size:0.85em;opacity:0.75;">${cfg.tracerLineSize ?? 1.5}px</span>
        </div>
      `);

                const hoverRow = makeRow("Player Hover", `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" class="xh-hover-highlight" ${cfg.hoverHighlight ? "checked" : ""} />
            Change color on player
          </label>
          <input type="color" class="xh-hover-color" value="${cfg.hoverColor || "#ffff00"}" title="Hover color" />
        </div>
      `);

                enabledRow.querySelector(".xh-enabled").addEventListener("change", (e) => {
                    cfg.enabled = e.target.checked;
                    syncCrosshair();
                });
                enabledRow.querySelector(".xh-color").addEventListener("input", (e) => {
                    cfg.color = e.target.value;
                    syncCrosshair();
                });
                styleRow.querySelector(".xh-style").addEventListener("change", (e) => {
                    cfg.style = e.target.value;
                    syncCrosshair();
                });
                sizeRow.querySelector(".xh-crosshair-size").addEventListener("input", (e) => {
                    const v = Number(e.target.value);
                    cfg.crosshairSize = v;
                    sizeRow.querySelector(".xh-crosshair-size-label").textContent = `${v}px`;
                    syncCrosshair();
                });
                lineSizeRow.querySelector(".xh-line-size").addEventListener("input", (e) => {
                    const v = Number(e.target.value);
                    cfg.lineSize = v;
                    lineSizeRow.querySelector(".xh-line-size-label").textContent = `${v}px`;
                    syncCrosshair();
                });
                lineRow.querySelector(".xh-show-line").addEventListener("change", (e) => {
                    cfg.showLine = e.target.checked;
                    syncCrosshair();
                });
                lineRow.querySelector(".xh-line-color").addEventListener("input", (e) => {
                    cfg.lineColor = e.target.value;
                    syncCrosshair();
                });
                tracerSizeRow.querySelector(".xh-tracer-size").addEventListener("input", (e) => {
                    const v = Number(e.target.value);
                    cfg.tracerLineSize = v;
                    tracerSizeRow.querySelector(".xh-tracer-size-label").textContent = `${v}px`;
                    syncCrosshair();
                });
                hoverRow.querySelector(".xh-hover-highlight").addEventListener("change", (e) => {
                    cfg.hoverHighlight = e.target.checked;
                    syncCrosshair();
                });
                hoverRow.querySelector(".xh-hover-color").addEventListener("input", (e) => {
                    cfg.hoverColor = e.target.value;
                    syncCrosshair();
                });

            } else if (moduleName === "Triggerbot (Autoshoot)") {
                const defaults = getTriggerAssistConfig();
                Object.assign(cfg, { ...defaults, ...cfg });
                window.__zyroxTriggerAssistConfig = { ...cfg };

                const syncTriggerAssist = () => {
                    window.__zyroxTriggerAssistConfig = { ...cfg };
                    saveSettings();
                };
                syncTriggerAssist();

                for (const setting of moduleLayout?.settings || []) {
                    if (setting.type === "checkbox") {
                        if (cfg[setting.id] === undefined) cfg[setting.id] = Boolean(setting.default);
                        const checked = cfg[setting.id] ? "checked" : "";
                        const card = document.createElement("div");
                        card.className = "zyrox-setting-card";
                        card.innerHTML = `
            <label>${setting.label}</label>
            <input type="checkbox" class="set-module-setting-checkbox" data-setting-id="${setting.id}" ${checked} />
          `;
                        configBody.appendChild(card);
                        const input = card.querySelector(".set-module-setting-checkbox");
                        input?.addEventListener("change", (event) => {
                            cfg[setting.id] = Boolean(event.target.checked);
                            syncTriggerAssist();
                        });
                    } else if (setting.type === "slider") {
                        const value = Number(cfg[setting.id] ?? setting.default ?? setting.min ?? 0);
                        const unit = setting.unit ?? "ms";
                        const card = document.createElement("div");
                        card.className = "zyrox-setting-card";
                        card.innerHTML = `
            <label style="display:flex;justify-content:space-between;align-items:center;">
              <span>${setting.label}</span>
              <span class="zyrox-slider-value" style="font-size:0.85em;opacity:0.75;min-width:52px;text-align:right;">${value}${unit}</span>
            </label>
            <input type="range" class="set-module-setting" data-setting-id="${setting.id}" min="${setting.min}" max="${setting.max}" step="${setting.step}" value="${value}" />
          `;
                        configBody.appendChild(card);
                        const slider = card.querySelector(".set-module-setting");
                        const valueLabel = card.querySelector(".zyrox-slider-value");
                        slider?.addEventListener("input", (event) => {
                            const next = Number(event.target.value);
                            cfg[setting.id] = next;
                            if (valueLabel) valueLabel.textContent = `${next}${unit}`;
                            syncTriggerAssist();
                        });
                    }
                }
            } else if (moduleName === "Aimbot") {
                const defaults = getAutoAimConfig();
                Object.assign(cfg, { ...defaults, ...cfg });
                window.__zyroxAutoAimConfig = { ...cfg };

                const syncAutoAim = () => {
                    window.__zyroxAutoAimConfig = { ...cfg };
                    saveSettings();
                };
                syncAutoAim();

                for (const setting of moduleLayout?.settings || []) {
                    if (setting.type === "checkbox") {
                        if (cfg[setting.id] === undefined) cfg[setting.id] = Boolean(setting.default);
                        const checked = cfg[setting.id] ? "checked" : "";
                        const card = document.createElement("div");
                        card.className = "zyrox-setting-card";
                        card.innerHTML = `
            <label>${setting.label}</label>
            <input type="checkbox" class="set-module-setting-checkbox" data-setting-id="${setting.id}" ${checked} />
          `;
                        configBody.appendChild(card);
                        const input = card.querySelector(".set-module-setting-checkbox");
                        input?.addEventListener("change", (event) => {
                            cfg[setting.id] = Boolean(event.target.checked);
                            syncAutoAim();
                        });
                    } else if (setting.type === "slider") {
                        const value = Number(cfg[setting.id] ?? setting.default ?? setting.min ?? 0);
                        const unit = setting.unit ?? "";
                        const card = document.createElement("div");
                        card.className = "zyrox-setting-card";
                        card.innerHTML = `
            <label style="display:flex;justify-content:space-between;align-items:center;">
              <span>${setting.label}</span>
              <span class="zyrox-slider-value" style="font-size:0.85em;opacity:0.75;min-width:52px;text-align:right;">${value}${unit}</span>
            </label>
            <input type="range" class="set-module-setting" data-setting-id="${setting.id}" min="${setting.min}" max="${setting.max}" step="${setting.step}" value="${value}" />
          `;
                        configBody.appendChild(card);
                        const slider = card.querySelector(".set-module-setting");
                        const valueLabel = card.querySelector(".zyrox-slider-value");
                        slider?.addEventListener("input", (event) => {
                            const next = Number(event.target.value);
                            cfg[setting.id] = next;
                            if (valueLabel) valueLabel.textContent = `${next}${unit}`;
                            syncAutoAim();
                        });
                    }
                }
            } else if (moduleName === "Auto Upgrade") {
                const defaults = getAutoUpgradeConfig();
                Object.assign(cfg, { ...defaults, ...cfg });
                const defaultOrder = [...AUTO_UPGRADE_TIE_BREAK_ORDER];
                const configuredOrder = Array.isArray(cfg.order) ? cfg.order.filter((key) => defaultOrder.includes(key)) : [];
                const order = [...configuredOrder];
                for (const key of defaultOrder) if (!order.includes(key)) order.push(key);
                cfg.order = [...order];
                autoUpgradeState.order = [...order];

                const settingCard = document.createElement("div");
                settingCard.style.display = "block";
                settingCard.style.width = "100%";
                settingCard.style.padding = "10px 0";
                settingCard.innerHTML = `<label style="display:block;margin-bottom:8px;">Upgrade Order</label>`;
                const list = document.createElement("div");
                list.style.display = "flex";
                list.style.flexDirection = "column";
                list.style.gap = "8px";
                list.style.marginTop = "2px";

                const rowByKey = new Map();
                const createRow = (key) => {
                    const row = document.createElement("div");
                    row.draggable = true;
                    row.dataset.upgradeKey = key;
                    row.style.display = "flex";
                    row.style.alignItems = "center";
                    row.style.justifyContent = "space-between";
                    row.style.padding = "8px 10px";
                    row.style.border = "1px solid rgba(255,255,255,.12)";
                    row.style.borderRadius = "8px";
                    row.style.background = "rgba(0,0,0,.22)";
                    row.style.cursor = "grab";
                    row.style.transition = "transform .12s ease, border-color .12s ease, background-color .12s ease, opacity .12s ease";
                    row.innerHTML = `
          <span style="display:flex;align-items:center;gap:8px;pointer-events:none;">
            <span style="opacity:.7;">☰</span>
            <span>${UPGRADE_HUD_LABELS[key]}</span>
          </span>
          <input type="checkbox" class="set-module-setting-checkbox" style="accent-color:var(--zyx-checkmark-color);" data-setting-id="${key}" ${cfg[key] ? "checked" : ""} />
        `;
                    row.querySelector(".set-module-setting-checkbox")?.addEventListener("change", (event) => {
                        cfg[key] = Boolean(event.target.checked);
                        autoUpgradeState.toggles[key] = cfg[key];
                        saveSettings();
                    });
                    rowByKey.set(key, row);
                    return row;
                };

                for (const key of order) list.appendChild(createRow(key));
                settingCard.appendChild(list);
                configBody.appendChild(settingCard);

                let draggingKey = null;
                const dropIndicator = document.createElement("div");
                dropIndicator.style.height = "0";
                dropIndicator.style.borderTop = "2px solid var(--zyx-slider-color)";
                dropIndicator.style.margin = "0";
                dropIndicator.style.borderRadius = "2px";
                dropIndicator.style.opacity = "0";
                dropIndicator.style.transition = "opacity .1s ease";

                list.addEventListener("dragstart", (event) => {
                    const row = event.target.closest("[data-upgrade-key]");
                    if (!row) return;
                    draggingKey = row.dataset.upgradeKey;
                    row.style.opacity = "0.55";
                    row.style.transform = "scale(0.985)";
                    row.style.borderColor = "var(--zyx-slider-color)";
                });
                list.addEventListener("dragend", () => {
                    draggingKey = null;
                    dropIndicator.remove();
                    for (const row of list.querySelectorAll("[data-upgrade-key]")) row.style.opacity = "1";
                    for (const row of list.querySelectorAll("[data-upgrade-key]")) {
                        row.style.transform = "scale(1)";
                        row.style.borderColor = "rgba(255,255,255,.12)";
                    }
                });
                list.addEventListener("dragover", (event) => {
                    event.preventDefault();
                    if (!draggingKey) return;
                    const rows = [...list.querySelectorAll("[data-upgrade-key]")].filter((row) => row.dataset.upgradeKey !== draggingKey);
                    let insertBeforeRow = null;
                    for (const row of rows) {
                        const rect = row.getBoundingClientRect();
                        if (event.clientY < rect.top + rect.height / 2) {
                            insertBeforeRow = row;
                            break;
                        }
                    }
                    if (insertBeforeRow) list.insertBefore(dropIndicator, insertBeforeRow);
                    else list.appendChild(dropIndicator);
                    dropIndicator.style.opacity = "1";
                });
                list.addEventListener("drop", (event) => {
                    event.preventDefault();
                    if (!draggingKey) return;
                    const draggedRow = rowByKey.get(draggingKey);
                    if (!draggedRow) return;
                    if (dropIndicator.parentElement === list) {
                        list.insertBefore(draggedRow, dropIndicator);
                    } else {
                        const dropTarget = event.target.closest("[data-upgrade-key]");
                        if (!dropTarget) list.appendChild(draggedRow);
                        else if (dropTarget !== draggedRow) dropTarget.before(draggedRow);
                    }
                    dropIndicator.remove();
                    const nextOrder = [...list.querySelectorAll("[data-upgrade-key]")].map((row) => row.dataset.upgradeKey);
                    cfg.order = nextOrder;
                    autoUpgradeState.order = [...nextOrder];
                    saveSettings();
                });
            } else if (moduleLayout && Array.isArray(moduleLayout.settings)) {
                for (const setting of moduleLayout.settings) {
                    const settingCard = document.createElement("div");
                    settingCard.className = "zyrox-setting-card";

                    if (setting.type === "slider") {
                        if (cfg[setting.id] === undefined) cfg[setting.id] = setting.default ?? setting.min ?? 0;
                        const initialVal = cfg[setting.id];
                        const valueUnit = setting.unit ?? "ms";
                        settingCard.innerHTML = `
            <label style="display:flex;justify-content:space-between;align-items:center;">
              <span>${setting.label}</span>
              <span class="zyrox-slider-value" style="font-size:0.85em;opacity:0.75;min-width:52px;text-align:right;">${initialVal}${valueUnit}</span>
            </label>
            <input type="range" class="set-module-setting" data-setting-id="${setting.id}" min="${setting.min}" max="${setting.max}" step="${setting.step}" value="${initialVal}" />
          `;
                        const settingInput = settingCard.querySelector(".set-module-setting");
                        const valueLabel = settingCard.querySelector(".zyrox-slider-value");
                        if (settingInput) {
                            settingInput.addEventListener("input", (event) => {
                                const newVal = Number(event.target.value);
                                cfg[setting.id] = newVal;
                                if (valueLabel) valueLabel.textContent = `${newVal}${valueUnit}`;
                                if (moduleName === "Auto Answer" && (setting.id === "speed" || setting.id === "triviaDelay")) {
                                    // Live-update answer delays only while Auto Answer is enabled
                                    if (state.enabledModules.has("Auto Answer")) {
                                        startAutoAnswer();
                                    }
                                }
                                if (moduleName === "Upgrade HUD" && setting.id === "hudSize") {
                                    let livePos = null;
                                    if (upgradeHudState.container) {
                                        livePos = readHudPositionFromElement(upgradeHudState.container);
                                        if (livePos) writeHudPosition("Upgrade HUD", livePos);
                                    }
                                    const patch = { hudSize: newVal, ...(livePos ? { hudPosition: { x: Math.round(livePos.x), y: Math.round(livePos.y) } } : {}) };
                                    const nextCfg = writeUpgradeHudConfigPatch(patch);
                                    upgradeHudLog("Upgrade HUD setting changed", { settingId: setting.id, value: newVal, livePos, nextCfg });
                                    renderUpgradeHud(nextCfg);
                                }
                                if (moduleName === "Building HUD" && setting.id === "hudSize") {
                                    let livePos = null;
                                    if (lavaBuildingHudState.container) {
                                        livePos = readHudPositionFromElement(lavaBuildingHudState.container);
                                        if (livePos) writeHudPosition("Building HUD", livePos);
                                    }
                                    const patch = { hudSize: newVal, ...(livePos ? { hudPosition: { x: Math.round(livePos.x), y: Math.round(livePos.y) } } : {}) };
                                    const nextCfg = writeBuildingHudConfigPatch(patch);
                                    upgradeHudLog("Building HUD setting changed", { settingId: setting.id, value: newVal, livePos, nextCfg });
                                    renderLavaBuildingHud(nextCfg);
                                }
                                if (moduleName === ABILITY_HUD_MODULE_NAME) {
                                    if (setting.id === "abilityHudScale" || setting.id === "abilityHudGap") {
                                        applyAbilityHudLiveConfig({ cfg });
                                    }
                                }
                                if (moduleName === CAMERA_ZOOM_MODULE_NAME && setting.id === "zoom") {
                                    cfg.zoom = clampCameraZoom(newVal);
                                    if (valueLabel) valueLabel.textContent = `${cfg.zoom}${valueUnit}`;
                                    if (state.enabledModules.has(CAMERA_ZOOM_MODULE_NAME)) showCameraZoomToast(cfg.zoom);
                                }
                                saveSettings();
                            });
                        }
                    }

                    if (setting.type === "checkbox") {
                        if (cfg[setting.id] === undefined) cfg[setting.id] = Boolean(setting.default);
                        const checked = cfg[setting.id] ? "checked" : "";
                        settingCard.innerHTML = `
            <label>${setting.label}</label>
            <input type="checkbox" class="set-module-setting-checkbox" data-setting-id="${setting.id}" ${checked} />
          `;
                        const settingInput = settingCard.querySelector(".set-module-setting-checkbox");
                        if (settingInput) {
                            settingInput.addEventListener("change", (event) => {
                                cfg[setting.id] = Boolean(event.target.checked);
                                if (moduleName === "Upgrade HUD" && (setting.id === "displayTitle" || setting.id === "showLvlPrefix" || setting.id === "showUpgradeButton")) {
                                    let livePos = null;
                                    if (upgradeHudState.container) {
                                        livePos = readHudPositionFromElement(upgradeHudState.container);
                                        if (livePos) writeHudPosition("Upgrade HUD", livePos);
                                    }
                                    const patch = { [setting.id]: cfg[setting.id], ...(livePos ? { hudPosition: { x: Math.round(livePos.x), y: Math.round(livePos.y) } } : {}) };
                                    const nextCfg = writeUpgradeHudConfigPatch(patch);
                                    upgradeHudLog("Upgrade HUD setting changed", { settingId: setting.id, value: cfg[setting.id], livePos, nextCfg });
                                    renderUpgradeHud(nextCfg);
                                }
                                if (moduleName === "Building HUD" && setting.id === "displayTitle") {
                                    let livePos = null;
                                    if (lavaBuildingHudState.container) {
                                        livePos = readHudPositionFromElement(lavaBuildingHudState.container);
                                        if (livePos) writeHudPosition("Building HUD", livePos);
                                    }
                                    const patch = { displayTitle: cfg[setting.id], ...(livePos ? { hudPosition: { x: Math.round(livePos.x), y: Math.round(livePos.y) } } : {}) };
                                    const nextCfg = writeBuildingHudConfigPatch(patch);
                                    upgradeHudLog("Building HUD setting changed", { settingId: setting.id, value: cfg[setting.id], livePos, nextCfg });
                                    renderLavaBuildingHud(nextCfg);
                                }
                                if (moduleName === "Auto Upgrade" && Object.prototype.hasOwnProperty.call(autoUpgradeState.toggles, setting.id)) {
                                    autoUpgradeState.toggles[setting.id] = Boolean(event.target.checked);
                                }
                                if (moduleName === ABILITY_HUD_MODULE_NAME && setting.id === "abilityHudShowPrices") {
                                    applyAbilityHudLiveConfig({ cfg });
                                }
                                if (moduleName === HIDE_POPUPS_MODULE_NAME) {
                                    syncHidePopups();
                                }
                                saveSettings();
                            });
                        }
                    }

                    if (setting.type === "select") {
                        if (cfg[setting.id] === undefined) cfg[setting.id] = setting.default ?? setting.options?.[0]?.value ?? "";
                        const options = Array.isArray(setting.options) ? setting.options : [];
                        const optionsHtml = options
                            .map((option) => {
                                const selected = String(option.value) === String(cfg[setting.id]) ? "selected" : "";
                                return `<option value="${option.value}" ${selected}>${option.label}</option>`;
                            })
                            .join("");
                        settingCard.innerHTML = `
            <label>${setting.label}</label>
            <select class="set-module-setting-select" data-setting-id="${setting.id}">${optionsHtml}</select>
          `;
                        const settingInput = settingCard.querySelector(".set-module-setting-select");
                        if (settingInput) {
                            settingInput.addEventListener("change", (event) => {
                                cfg[setting.id] = String(event.target.value);
                                if (moduleName === "Answer Popup" && setting.id === "preset") {
                                    applyAnswerPopupPreset(cfg, cfg[setting.id]);
                                    openConfig(moduleName);
                                }
                                if (moduleName === "Answer Popup") refreshVisibleAnswerPopup();
                                if (moduleName === ABILITY_HUD_MODULE_NAME) {
                                    if (setting.id === "abilityHudDisplayMode") openConfig(moduleName);
                                    applyAbilityHudLiveConfig({ cfg });
                                }
                                saveSettings();
                            });
                        }
                    }

                    if (setting.type === "color") {
                        if (cfg[setting.id] === undefined) cfg[setting.id] = setting.default ?? "#ffffff";
                        settingCard.innerHTML = `
            <label>${setting.label}</label>
            <input type="color" class="set-module-setting-color" data-setting-id="${setting.id}" value="${cfg[setting.id]}" />
          `;
                        const settingInput = settingCard.querySelector(".set-module-setting-color");
                        if (settingInput) {
                            settingInput.addEventListener("input", (event) => {
                                cfg[setting.id] = String(event.target.value || "#ffffff");
                                if (moduleName === "Answer Popup") refreshVisibleAnswerPopup();
                                saveSettings();
                            });
                        }
                    }

                    if (setting.type === "text") {
                        if (cfg[setting.id] === undefined) cfg[setting.id] = String(setting.default ?? "");
                        const safeValue = String(cfg[setting.id]).replace(/"/g, "&quot;");
                        settingCard.innerHTML = `
            <label>${setting.label}</label>
            <input type="text" class="set-module-setting-text" data-setting-id="${setting.id}" value="${safeValue}" />
          `;
                        const settingInput = settingCard.querySelector(".set-module-setting-text");
                        if (settingInput) {
                            settingInput.addEventListener("input", (event) => {
                                cfg[setting.id] = String(event.target.value ?? "");
                                saveSettings();
                            });
                        }
                    }

                    if (settingCard.innerHTML.trim()) configBody.appendChild(settingCard);
                }
            }

            configTitleEl.textContent = moduleName;
            configSubEl.textContent = getModuleDescription(moduleName);
            setBindButtonText("Set keybind");
            setCurrentBindText(cfg.keybind || null);

            configBackdrop.classList.remove("hidden");
            configMenu.classList.remove("hidden");
            settingsMenu.classList.add("hidden");
        }

        function openSettings() {
            configBackdrop.classList.remove("hidden");
            settingsMenu.classList.remove("hidden");
            configMenu.classList.add("hidden");
        }

        function collectSettings() {
            try {
                if (upgradeHudState?.container?.isConnected) {
                    const pos = readHudPositionFromElement(upgradeHudState.container);
                    if (pos) {
                        const cfg = getHudModuleConfigObject("Upgrade HUD", { displayTitle: true, showLvlPrefix: false, showUpgradeButton: true, hudSize: 100, hudPosition: null });
                        if (cfg && typeof cfg === "object") { cfg.hudPosition = { x: Math.round(pos.x), y: Math.round(pos.y) }; console.log("[HUD Position] Stored before settings save", { moduleName: "Upgrade HUD", hudPosition: { ...cfg.hudPosition } }); }
                    }
                }
                if (lavaBuildingHudState?.container?.isConnected) {
                    const pos = readHudPositionFromElement(lavaBuildingHudState.container);
                    if (pos) {
                        const cfg = getHudModuleConfigObject("Building HUD", { displayTitle: true, hudSize: 100, hudPosition: null });
                        if (cfg && typeof cfg === "object") { cfg.hudPosition = { x: Math.round(pos.x), y: Math.round(pos.y) }; console.log("[HUD Position] Stored before settings save", { moduleName: "Building HUD", hudPosition: { ...cfg.hudPosition } }); }
                    }
                }
                if (abilityHudState?.container?.isConnected) {
                    const pos = readHudPositionFromElement(abilityHudState.container);
                    if (pos) {
                        const cfg = moduleCfg(ABILITY_HUD_MODULE_NAME);
                        if (cfg && typeof cfg === "object") { cfg.hudPosition = { x: Math.round(pos.x), y: Math.round(pos.y) }; console.log("[HUD Position] Stored before settings save", { moduleName: ABILITY_HUD_MODULE_NAME, hudPosition: { ...cfg.hudPosition } }); }
                    }
                }
            } catch (_) { }
            return {
                toggleKey: CONFIG.toggleKey,
                globalPreset: state.globalPreset,
                searchAutofocus: searchAutofocusInput.checked,
                accent: accentInput.value,
                shellBgStart: shellBgStartInput.value,
                shellBgEnd: shellBgEndInput.value,
                topbarColor: topbarColorInput.value,
                iconColor: iconColorInput.value,
                outlineColor: outlineColorInput.value,
                panelCountText: panelCountTextInput.value,
                panelCountBorder: panelCountBorderInput.value,
                panelCountBg: panelCountBgInput.value,
                border: borderInput.value,
                text: textInput.value,
                opacity: opacityInput.value,
                sliderColor: sliderColorInput.value,
                checkmarkColor: checkmarkColorInput.value,
                selectBg: selectBgInput.value,
                selectText: selectTextInput.value,
                inputBg: inputBgInput.value,
                inputText: inputTextInput.value,
                mutedText: mutedTextInput.value,
                accentSoft: accentSoftInput.value,
                searchText: searchTextInput.value,
                font: fontInput.value,
                headerStart: headerStartInput.value,
                headerEnd: headerEndInput.value,
                headerText: headerTextInput.value,
                settingsHeaderStart: settingsHeaderStartInput.value,
                settingsHeaderEnd: settingsHeaderEndInput.value,
                settingsSidebar: settingsSidebarInput.value,
                settingsBody: settingsBodyInput.value,
                settingsText: settingsTextInput.value,
                settingsSubtext: settingsSubtextInput.value,
                settingsCardBorder: settingsCardBorderInput.value,
                settingsCardBg: settingsCardBgInput.value,
                espValueTextColor: espValueTextColorInput.value,
                scale: scaleInput.value,
                radius: radiusInput.value,
                blur: blurInput.value,
                hoverShift: hoverShiftInput.value,
                displayMode: state.displayMode,
                looseInitialized: state.looseInitialized,
                loosePositions: state.loosePositions,
                loosePanelPositions: state.loosePanelPositions,
                collapsedPanels: state.collapsedPanels,
                hiddenCategories: state.hiddenCategories,
                enabledModules: Array.from(state.enabledModules),
                moduleConfig: Array.from(ensureModuleConfigStore().entries()),
            };
        }

        function setPanelCollapsed(panelName, collapsed) {
            const panel = panelByName.get(panelName);
            if (!panel) return;
            const list = panel.querySelector(".zyrox-module-list");
            if (!list) return;
            state.collapsedPanels[panelName] = collapsed;
            list.style.display = collapsed ? "none" : "";
            const button = panelCollapseButtons.get(panelName);
            if (button) {
                button.textContent = collapsed ? "▸" : "▾";
                button.title = collapsed ? "Expand category" : "Collapse category";
                button.setAttribute("aria-label", button.title);
                button.classList.toggle("collapsed", collapsed);
            }
        }

        function syncCollapseButtons() {
            for (const [panelName, button] of panelCollapseButtons.entries()) {
                const collapsed = !!state.collapsedPanels[panelName];
                button.textContent = collapsed ? "▸" : "▾";
                button.title = collapsed ? "Expand category" : "Collapse category";
                button.setAttribute("aria-label", button.title);
                button.classList.toggle("collapsed", collapsed);
            }
        }

        function isPanelHidden(panelName) {
            return !!state.hiddenCategories[panelName];
        }

        function setPanelHidden(panelName, hidden) {
            state.hiddenCategories[panelName] = !!hidden;
            applySearchFilter();

        }

        function clampToViewport(x, y, el) {
            const rect = el.getBoundingClientRect();
            const maxX = Math.max(0, window.innerWidth - rect.width);
            const maxY = Math.max(0, window.innerHeight - rect.height);
            return {
                x: Math.max(0, Math.min(x, maxX)),
                y: Math.max(0, Math.min(y, maxY)),
            };
        }

        function getShellScale() {
            const transform = getComputedStyle(shell).transform;
            if (!transform || transform === "none") return 1;
            const matrix = transform.match(/^matrix\((.+)\)$/);
            if (!matrix) return 1;
            const values = matrix[1].split(",").map((v) => Number(v.trim()));
            if (values.length < 4 || values.some((v) => !Number.isFinite(v))) return 1;
            const [a, b] = values;
            return Math.max(0.01, Math.hypot(a, b));
        }

        function clampLoosePosition(x, y, el, scale, shellRect) {
            const rect = el.getBoundingClientRect();
            const minX = -shellRect.left / scale;
            const minY = -shellRect.top / scale;
            const maxX = (window.innerWidth - shellRect.left - rect.width) / scale;
            const maxY = (window.innerHeight - shellRect.top - rect.height) / scale;
            return {
                x: Math.max(minX, Math.min(x, maxX)),
                y: Math.max(minY, Math.min(y, maxY)),
            };
        }

        let dragState = null;
        let resizeState = null;
        let hasPositionChanges = false;
        let hasSizeChanges = false;

        const panelDragState = { panelName: null, offsetX: 0, offsetY: 0, shellLeft: 0, shellTop: 0, scale: 1 };

        function normalizeDisplayMode(value) {
            return value === "merged" ? "merged" : "loose";
        }

        function normalizeLoosePoint(value, fallbackX, fallbackY) {
            const x = Number(value?.x);
            const y = Number(value?.y);
            return {
                x: Number.isFinite(x) ? x : fallbackX,
                y: Number.isFinite(y) ? y : fallbackY,
            };
        }

        function getMergedPanelPositionsSnapshot() {
            const snapshot = {};
            shell.classList.remove("loose-mode");
            const shellRect = shell.getBoundingClientRect();
            for (const [name, panel] of panelByName.entries()) {
                const rect = panel.getBoundingClientRect();
                snapshot[name] = {
                    x: Math.round(rect.left - shellRect.left),
                    y: Math.round(rect.top - shellRect.top),
                };
            }
            return snapshot;
        }

        function setDisplayMode(mode) {
            const nextMode = normalizeDisplayMode(mode);
            const mergedSnapshot = nextMode === "loose" ? getMergedPanelPositionsSnapshot() : null;

            if (nextMode === "loose" && !state.looseInitialized) {
                // Capture while still in merged flow layout so the first loose layout mirrors merged positions.
                state.loosePanelPositions = { ...mergedSnapshot };
                state.looseInitialized = true;
            }

            state.displayMode = nextMode;
            shell.classList.toggle("loose-mode", state.displayMode === "loose");

            for (const btn of displayModeButtons) {
                btn.classList.toggle("active", btn.dataset.displayMode === state.displayMode);
            }

            if (state.displayMode === "loose") {
                shell.style.width = "";
                shell.style.height = "";
                state.mergedRootPosition = {
                    left: parseInt(root.style.left || "20", 10),
                    top: parseInt(root.style.top || "28", 10),
                };
                root.style.left = "0px";
                root.style.top = "0px";

                const shellRect = shell.getBoundingClientRect();
                const scale = getShellScale();
                state.loosePositions.topbar = normalizeLoosePoint(state.loosePositions?.topbar, 12, 12);
                const clampedTopbar = clampLoosePosition(state.loosePositions.topbar.x, state.loosePositions.topbar.y, topbar, scale, shellRect);
                state.loosePositions.topbar = clampedTopbar;
                topbar.style.left = `${clampedTopbar.x}px`;
                topbar.style.top = `${clampedTopbar.y}px`;

                let panelIndex = 0;
                for (const [name, panel] of panelByName.entries()) {
                    const existingRect = panel.getBoundingClientRect();
                    const snapshotPos = mergedSnapshot?.[name];
                    const hasRenderableSize = existingRect.width > 0 && existingRect.height > 0;
                    const safeSnapshotPos = hasRenderableSize ? snapshotPos : null;
                    const safeFallbackPos = hasRenderableSize
                        ? {
                            x: Math.round((existingRect.left - shellRect.left) / Math.max(scale, 0.001)),
                            y: Math.round((existingRect.top - shellRect.top) / Math.max(scale, 0.001)),
                        }
                        : { x: 16 + panelIndex * 22, y: 68 + panelIndex * 18 };
                    const pos = state.loosePanelPositions[name]
                        || safeSnapshotPos
                        || safeFallbackPos;
                    const clamped = clampLoosePosition(pos.x, pos.y, panel, scale, shellRect);
                    state.loosePanelPositions[name] = clamped;
                    panel.style.left = `${clamped.x}px`;
                    panel.style.top = `${clamped.y}px`;
                    panelIndex += 1;
                }
            } else {
                root.style.left = `${state.mergedRootPosition.left}px`;
                root.style.top = `${state.mergedRootPosition.top}px`;
                topbar.style.left = "";
                topbar.style.top = "";
                for (const panel of panelByName.values()) {
                    panel.style.left = "";
                    panel.style.top = "";
                }
                shell.style.width = `${state.shellWidth}px`;
                shell.style.height = `${state.shellHeight}px`;
            }
        }

        function applyPreset(presetName) {
            state.globalPreset = normalizePopupPresetName(presetName || "default");
            const popupCfg = getModuleConfigSafe("Answer Popup");
            popupCfg.preset = state.globalPreset;
            applyAnswerPopupPreset(popupCfg, state.globalPreset);
            const preset = (() => {
                if (state.globalPreset === "green") {
                    return {
                        accent: "#2dff75", shellStart: "#2dff75", shellEnd: "#03130a", topbar: "#35d96d", border: "#5dff9a",
                        outline: "#37d878", text: "#d7ffe6", muted: "#88b79b", soft: "#a8ffd0", search: "#e6fff0", icon: "#d7ffe9",
                        panelText: "#d9ffe8", panelBorder: "#5fff99", panelBg: "#04110a", slider: "#2dff75", checkmark: "#2dff75",
                        selectBg: "#111e16", selectText: "#d7ffe6",
                        headerStart: "#2dff75", headerEnd: "#0f2f1b", headerText: "#f0fff4",
                        settingsText: "#d7ffe6", settingsSubtext: "#a7cfb7", settingsSidebar: "#102016", settingsBody: "#0d1510",
                        settingsCardBorder: "#79d6a0", settingsCardBg: "#12301f",
                        settingsHeaderStart: "#2dff75", settingsHeaderEnd: "#0f2f1b", espValueTextColor: "#ffffff",
                        font: "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
                    };
                }
                if (state.globalPreset === "ice") {
                    return {
                        accent: "#6cd8ff", shellStart: "#6cd8ff", shellEnd: "#07131a", topbar: "#58bff1", border: "#8ae4ff",
                        outline: "#6fbce8", text: "#d7edff", muted: "#8ea7bd", soft: "#b8e5ff", search: "#e7f5ff", icon: "#dff3ff",
                        panelText: "#e1f4ff", panelBorder: "#8fd7ff", panelBg: "#071019", slider: "#7bdfff", checkmark: "#7bdfff",
                        selectBg: "#0c1c26", selectText: "#d7edff",
                        headerStart: "#6cd8ff", headerEnd: "#133042", headerText: "#f4fbff",
                        settingsText: "#d7edff", settingsSubtext: "#9db4c6", settingsSidebar: "#10202c", settingsBody: "#0e141a",
                        settingsCardBorder: "#90cae8", settingsCardBg: "#173247",
                        settingsHeaderStart: "#6cd8ff", settingsHeaderEnd: "#133042", espValueTextColor: "#ffffff",
                        font: "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
                    };
                }
                if (state.globalPreset === "grayscale") {
                    return {
                        accent: "#d3d3d3", shellStart: "#7a7a7a", shellEnd: "#0a0a0a", topbar: "#8d8d8d", border: "#b1b1b1",
                        outline: "#9a9a9a", text: "#dddddd", muted: "#9a9a9a", soft: "#c9c9c9", search: "#f1f1f1", icon: "#f5f5f5",
                        panelText: "#efefef", panelBorder: "#a0a0a0", panelBg: "#0f0f0f", slider: "#c4c4c4", checkmark: "#d0d0d0",
                        selectBg: "#1b1b1b", selectText: "#efefef",
                        headerStart: "#8f8f8f", headerEnd: "#1d1d1d", headerText: "#ffffff",
                        settingsText: "#efefef", settingsSubtext: "#b2b2b2", settingsSidebar: "#202020", settingsBody: "#181818",
                        settingsCardBorder: "#b7b7b7", settingsCardBg: "#313131",
                        settingsHeaderStart: "#8f8f8f", settingsHeaderEnd: "#1d1d1d", espValueTextColor: "#ffffff",
                        font: "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
                    };
                }
                // Default (red)
                return {
                    accent: "#ff3d3d", shellStart: "#ff3d3d", shellEnd: "#000000", topbar: "#ff4a4a", border: "#ff6f6f",
                    outline: "#ff5b5b", text: "#d6d6df", muted: "#9b9bab", soft: "#ffbdbd", search: "#ffe6e6", icon: "#ffdada",
                    panelText: "#ffd9d9", panelBorder: "#ff6464", panelBg: "#1a1a1e", slider: "#ff6b6b", checkmark: "#ff6b6b",
                    selectBg: "#17171f", selectText: "#ffe5e5",
                    headerStart: "#ff4a4a", headerEnd: "#3c1212", headerText: "#ffffff",
                    settingsText: "#ffe5e5", settingsSubtext: "#c2c2ce", settingsSidebar: "#181820", settingsBody: "#121216",
                    settingsCardBorder: "#ffffff", settingsCardBg: "#ffffff",
                    settingsHeaderStart: "#ff3d3d", settingsHeaderEnd: "#2d0c0c", espValueTextColor: "#ffffff",
                    font: "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
                };
            })();

            accentInput.value = preset.accent;
            shellBgStartInput.value = preset.shellStart;
            shellBgEndInput.value = preset.shellEnd;
            topbarColorInput.value = preset.topbar;
            borderInput.value = preset.border;
            outlineColorInput.value = preset.outline;
            textInput.value = preset.text;
            mutedTextInput.value = preset.muted;
            accentSoftInput.value = preset.soft;
            searchTextInput.value = preset.search;
            fontInput.value = preset.font || "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif";
            iconColorInput.value = preset.icon;
            panelCountTextInput.value = preset.panelText;
            panelCountBorderInput.value = preset.panelBorder;
            panelCountBgInput.value = preset.panelBg;
            sliderColorInput.value = preset.slider;
            checkmarkColorInput.value = preset.checkmark;
            selectBgInput.value = preset.selectBg;
            selectTextInput.value = preset.selectText;
            inputBgInput.value = preset.selectBg;
            inputTextInput.value = preset.selectText;
            headerStartInput.value = preset.headerStart;
            headerEndInput.value = preset.headerEnd;
            headerTextInput.value = preset.headerText;
            settingsHeaderStartInput.value = preset.settingsHeaderStart;
            settingsHeaderEndInput.value = preset.settingsHeaderEnd;
            settingsSidebarInput.value = preset.settingsSidebar;
            settingsBodyInput.value = preset.settingsBody;
            settingsTextInput.value = preset.settingsText;
            settingsSubtextInput.value = preset.settingsSubtext;
            settingsCardBorderInput.value = preset.settingsCardBorder;
            settingsCardBgInput.value = preset.settingsCardBg;
            espValueTextColorInput.value = preset.espValueTextColor;
            applyAppearance();
            refreshVisibleAnswerPopup();
            saveSettings();
        }

        function applyAppearance() {
            const normalizeHex = (value, fallback) => {
                const normalized = String(value || "").trim();
                return /^#([0-9a-fA-F]{6})$/.test(normalized) ? normalized.toLowerCase() : fallback;
            };
            const clampNumber = (value, min, max, fallback) => {
                const parsed = Number(value);
                if (!Number.isFinite(parsed)) return fallback;
                return Math.min(max, Math.max(min, parsed));
            };
            const toRgba = (hex, alpha) => {
                const h = hex.replace("#", "");
                const r = parseInt(h.slice(0, 2), 16);
                const g = parseInt(h.slice(2, 4), 16);
                const b = parseInt(h.slice(4, 6), 16);
                return `rgba(${r}, ${g}, ${b}, ${alpha})`;
            };
            const darken = (hex, factor) => {
                const h = hex.replace("#", "");
                const r = Math.max(0, Math.floor(parseInt(h.slice(0, 2), 16) * factor));
                const g = Math.max(0, Math.floor(parseInt(h.slice(2, 4), 16) * factor));
                const b = Math.max(0, Math.floor(parseInt(h.slice(4, 6), 16) * factor));
                return `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
            };

            const shellBgStart = normalizeHex(shellBgStartInput.value, "#ff3d3d");
            const shellBgEnd = normalizeHex(shellBgEndInput.value, "#000000");
            const topbarColor = normalizeHex(topbarColorInput.value, "#ff4a4a");
            const iconColor = normalizeHex(iconColorInput.value, "#ffdada");
            const outlineColor = normalizeHex(outlineColorInput.value, "#ff5b5b");
            const panelCountText = normalizeHex(panelCountTextInput.value, "#ffd9d9");
            const panelCountBorder = normalizeHex(panelCountBorderInput.value, "#ff6464");
            const panelCountBg = normalizeHex(panelCountBgInput.value, "#1a1a1e");
            const border = normalizeHex(borderInput.value, "#ff6f6f");
            const text = normalizeHex(textInput.value, "#d6d6df");
            const opacity = clampNumber(opacityInput.value, 10, 100, 45) / 100;
            const sliderColor = normalizeHex(sliderColorInput.value, "#ff6b6b");
            const checkmarkColor = normalizeHex(checkmarkColorInput.value, "#ff6b6b");
            const selectBg = normalizeHex(selectBgInput.value, "#17171f");
            const selectText = normalizeHex(selectTextInput.value, "#ffe5e5");
            const inputBg = normalizeHex(inputBgInput.value, "#17171f");
            const inputText = normalizeHex(inputTextInput.value, "#ffe5e5");
            const mutedText = normalizeHex(mutedTextInput.value, "#9b9bab");
            const accentSoft = normalizeHex(accentSoftInput.value, "#ffbdbd");
            const searchText = normalizeHex(searchTextInput.value, "#ffe6e6");
            const font = fontInput.value;
            const headerStart = normalizeHex(headerStartInput.value, "#ff4a4a");
            const headerEnd = normalizeHex(headerEndInput.value, "#3c1212");
            const headerText = normalizeHex(headerTextInput.value, "#ffffff");
            const settingsHeaderStart = normalizeHex(settingsHeaderStartInput.value, "#ff3d3d");
            const settingsHeaderEnd = normalizeHex(settingsHeaderEndInput.value, "#2d0c0c");
            const settingsSidebar = normalizeHex(settingsSidebarInput.value, "#181820");
            const settingsBody = normalizeHex(settingsBodyInput.value, "#121216");
            const settingsText = normalizeHex(settingsTextInput.value, "#ffe5e5");
            const settingsSubtext = normalizeHex(settingsSubtextInput.value, "#c2c2ce");
            const settingsCardBorder = normalizeHex(settingsCardBorderInput.value, "#ffffff");
            const settingsCardBg = normalizeHex(settingsCardBgInput.value, "#ffffff");
            const espValueTextColor = normalizeHex(espValueTextColorInput.value, "#ffffff");
            const scale = clampNumber(scaleInput.value, 80, 130, 100) / 100;
            const radius = clampNumber(radiusInput.value, 8, 22, 14);
            const blur = clampNumber(blurInput.value, 0, 24, 10);
            const hoverShift = clampNumber(hoverShiftInput.value, 0, 8, 2);
            const themeTargets = [root.style, configBackdrop.style];
            const setThemeVar = (name, value) => {
                for (const target of themeTargets) target.setProperty(name, value);
            };
            setThemeVar("--zyx-border", `${border}99`);
            setThemeVar("--zyx-text", text);
            setThemeVar("--zyx-font", font);
            setThemeVar("--zyx-muted", mutedText);
            setThemeVar("--zyx-accent-soft", accentSoft);
            setThemeVar("--zyx-search-text", searchText);
            setThemeVar("--zyx-topbar-bg-start", toRgba(topbarColor, 0.22));
            setThemeVar("--zyx-topbar-bg-end", toRgba(darken(topbarColor, 0.22), 0.9));
            setThemeVar("--zyx-module-hover-bg", toRgba(topbarColor, 0.16));
            setThemeVar("--zyx-module-hover-border", toRgba(topbarColor, 0.4));
            setThemeVar("--zyx-module-active-start", toRgba(headerStart, 0.35));
            setThemeVar("--zyx-module-active-end", toRgba(headerEnd, 0.82));
            setThemeVar("--zyx-module-active-border", toRgba(headerStart, 0.55));
            setThemeVar("--zyx-icon-color", iconColor);
            setThemeVar("--zyx-outline-color", `${outlineColor}cc`);
            setThemeVar("--zyx-panel-count-text", panelCountText);
            setThemeVar("--zyx-panel-count-border", toRgba(panelCountBorder, 0.45));
            setThemeVar("--zyx-panel-count-bg", toRgba(panelCountBg, 0.6));
            setThemeVar("--zyx-header-bg-start", toRgba(headerStart, 0.24));
            setThemeVar("--zyx-header-bg-end", toRgba(headerEnd, 0.92));
            setThemeVar("--zyx-header-text", headerText);
            setThemeVar("--zyx-settings-header-start", toRgba(settingsHeaderStart, 0.3));
            setThemeVar("--zyx-settings-header-end", toRgba(settingsHeaderEnd, 0.95));
            setThemeVar("--zyx-settings-sidebar-bg", toRgba(settingsSidebar, 0.22));
            setThemeVar("--zyx-settings-body-bg", `linear-gradient(180deg, ${toRgba(settingsBody, 0.97)}, rgba(8, 8, 10, 0.97))`);
            setThemeVar("--zyx-settings-text", settingsText);
            setThemeVar("--zyx-settings-subtext", settingsSubtext);
            setThemeVar("--zyx-settings-card-border", toRgba(settingsCardBorder, 0.18));
            setThemeVar("--zyx-settings-card-bg", toRgba(settingsCardBg, 0.05));
            setThemeVar("--zyx-slider-color", sliderColor);
            setThemeVar("--zyx-checkmark-color", checkmarkColor);
            setThemeVar("--zyx-select-bg", toRgba(selectBg, 0.9));
            setThemeVar("--zyx-select-text", selectText);
            setThemeVar("--zyx-input-bg", toRgba(inputBg, 0.9));
            setThemeVar("--zyx-input-text", inputText);
            window.__zyroxEspValueTextColor = espValueTextColor;
            window.__zyroxEspConfig = { ...getEspRenderConfig(), valueTextColor: espValueTextColor, font: font };
            setThemeVar("--zyx-radius-xl", `${radius}px`);
            setThemeVar("--zyx-radius-lg", `${Math.max(4, radius - 2)}px`);
            setThemeVar("--zyx-radius-md", `${Math.max(3, radius - 4)}px`);
            setThemeVar("--zyx-hover-shift", `${hoverShift}px`);
            shell.style.transform = `scale(${scale.toFixed(2)})`;
            shell.style.transformOrigin = "top left";
            shell.style.background = `linear-gradient(150deg, ${toRgba(shellBgStart, 0.22)}, ${toRgba(shellBgEnd, opacity.toFixed(2))})`;
            setThemeVar("--zyx-shell-blur", `${blur}px`);
            shell.style.backdropFilter = `blur(var(--zyx-shell-blur)) saturate(115%)`;

            // FIX: derive button accent background from outlineColor so buttons always match the theme
            setThemeVar("--zyx-btn-bg", toRgba(outlineColor, 0.12));
            setThemeVar("--zyx-btn-hover-bg", toRgba(outlineColor, 0.2));

            if (state.displayMode === "loose") {
                const shellRect = shell.getBoundingClientRect();
                const looseScale = getShellScale();
                for (const [name, panel] of panelByName.entries()) {
                    const existingRect = panel.getBoundingClientRect();
                    const fallback = {
                        x: Math.round((existingRect.left - shellRect.left) / Math.max(looseScale, 0.001)),
                        y: Math.round((existingRect.top - shellRect.top) / Math.max(looseScale, 0.001)),
                    };
                    const current = state.loosePanelPositions[name] || fallback;
                    const clamped = clampLoosePosition(current.x, current.y, panel, looseScale, shellRect);
                    state.loosePanelPositions[name] = clamped;
                    panel.style.left = `${clamped.x}px`;
                    panel.style.top = `${clamped.y}px`;
                    hasPositionChanges = true;
                }
            }
        }

        function applySearchFilter() {
            const query = state.searchQuery.trim().toLowerCase();

            for (const entry of state.moduleEntries) {
                const visibleByQuery = !query || entry.name.toLowerCase().includes(query);
                entry.item.style.display = visibleByQuery ? "" : "none";
            }

            for (const [panel, meta] of state.modulePanels.entries()) {
                const panelName = panel.dataset.panelName || "";
                if (isPanelHidden(panelName)) {
                    panel.style.display = "none";
                    continue;
                }
                let visibleCount = 0;
                for (const moduleName of meta.modules) {
                    const item = state.moduleItems.get(moduleName);
                    if (item && item.style.display !== "none") visibleCount += 1;
                }

                panel.style.display = visibleCount > 0 ? "" : "none";
            }
        }

        function buildPanel(name, modules) {
            const panel = document.createElement("section");
            panel.className = "zyrox-panel";
            panel.dataset.panelName = name;

            const header = document.createElement("header");
            header.className = "zyrox-panel-header";

            const title = document.createElement("span");
            title.textContent = name;

            const collapseButton = document.createElement("span");
            collapseButton.className = "zyrox-panel-collapse-btn";
            collapseButton.textContent = "▾";
            collapseButton.title = "Collapse category";
            collapseButton.setAttribute("role", "button");
            collapseButton.setAttribute("tabindex", "0");
            collapseButton.setAttribute("aria-label", "Collapse category");
            const toggleCollapsed = (event) => {
                event.stopPropagation();
                const nextCollapsed = !state.collapsedPanels[name];
                setPanelCollapsed(name, nextCollapsed);
                saveSettings();
            };
            collapseButton.addEventListener("click", toggleCollapsed);
            collapseButton.addEventListener("keydown", (event) => {
                if (event.key !== "Enter" && event.key !== " ") return;
                event.preventDefault();
                toggleCollapsed(event);
            });

            header.appendChild(title);
            header.appendChild(collapseButton);

            const list = document.createElement("ul");
            list.className = "zyrox-module-list";

            const moduleNames = [];
            for (const moduleDef of modules) {
                const moduleName = typeof moduleDef === "string" ? moduleDef : moduleDef?.name;
                if (!moduleName) continue;
                if (state.moduleItems.has(moduleName)) continue;
                moduleNames.push(moduleName);
                const item = document.createElement("li");
                item.className = "zyrox-module";
                item.innerHTML = `<span>${moduleName}</span><span class="zyrox-bind-label"></span>`;

                state.moduleItems.set(moduleName, item);
                state.moduleEntries.push({ name: moduleName, item, panel });

                const behavior = MODULE_BEHAVIORS[moduleName];
                const moduleInstance = new Module(moduleName, {
                    onEnable: () => {
                        console.log(`[Zyrox] ${moduleName} enable requested`);
                        try {
                            if (behavior?.onEnable) behavior.onEnable();
                            console.log(`[Zyrox] ${moduleName} enabled`);
                        } catch (error) {
                            console.error(`[Zyrox] ${moduleName} failed to enable`, error);
                        }
                    },
                    onDisable: () => {
                        console.log(`[Zyrox] ${moduleName} disable requested`);
                        try {
                            if (behavior?.onDisable) behavior.onDisable();
                            console.log(`[Zyrox] ${moduleName} disabled`);
                        } catch (error) {
                            console.error(`[Zyrox] ${moduleName} failed to disable`, error);
                        }
                    },
                });
                state.modules.set(moduleName, moduleInstance);

                moduleCfg(moduleName);
                setBindLabel(item, moduleName);

                item.addEventListener("click", () => {
                    toggleModule(moduleName);
                });

                item.addEventListener("contextmenu", (event) => {
                    event.preventDefault();
                    openConfig(moduleName);
                });

                list.appendChild(item);
            }

            panel.appendChild(header);
            panel.appendChild(list);
            panelByName.set(name, panel);
            panelCollapseButtons.set(name, collapseButton);
            state.modulePanels.set(panel, { modules: moduleNames });
            return panel;
        }

        settingsMenuKeyBtn.addEventListener("click", () => {
            state.listeningForMenuBind = true;
            settingsMenuKeyBtn.textContent = "Press key...";
            searchInput.blur();
        });

        settingsMenuKeyResetBtn.addEventListener("click", () => {
            CONFIG.toggleKey = CONFIG.defaultToggleKey;
            settingsMenuKeyBtn.textContent = `Menu Key: ${CONFIG.toggleKey}`;
            setFooterText();
            state.listeningForMenuBind = false;
            saveSettings();
        });

        presetButtons.forEach((btn) => {
            btn.addEventListener("click", () => applyPreset(btn.dataset.preset || "default"));
        });

        settingsBtn.addEventListener("click", () => {
            openSettings();
        });

        settingsTabs.forEach((tab) => {
            tab.addEventListener("click", () => {
                const target = tab.dataset.tab;
                for (const t of settingsTabs) t.classList.toggle("active", t === tab);
                for (const pane of settingsPanes) pane.classList.toggle("hidden", pane.dataset.pane !== target);
            });
        });

        searchInput.addEventListener("keydown", (event) => {
            event.stopPropagation();
            if (event.key === CONFIG.toggleKey) {
                event.preventDefault();
                setVisible(false);
            }
        });

        const applySearchFilterDebounced = debounce(applySearchFilter, 80);
        searchInput.addEventListener("input", () => {
            state.searchQuery = searchInput.value;
            applySearchFilterDebounced();
        });

        accentInput.addEventListener("input", applyAppearance);
        shellBgStartInput.addEventListener("input", applyAppearance);
        shellBgEndInput.addEventListener("input", applyAppearance);
        topbarColorInput.addEventListener("input", applyAppearance);
        iconColorInput.addEventListener("input", applyAppearance);
        outlineColorInput.addEventListener("input", applyAppearance);
        panelCountTextInput.addEventListener("input", applyAppearance);
        panelCountBorderInput.addEventListener("input", applyAppearance);
        panelCountBgInput.addEventListener("input", applyAppearance);
        borderInput.addEventListener("input", applyAppearance);
        textInput.addEventListener("input", applyAppearance);
        opacityInput.addEventListener("input", applyAppearance);
        sliderColorInput.addEventListener("input", applyAppearance);
        checkmarkColorInput.addEventListener("input", applyAppearance);
        mutedTextInput.addEventListener("input", applyAppearance);
        accentSoftInput.addEventListener("input", applyAppearance);
        searchTextInput.addEventListener("input", applyAppearance);
        fontInput.addEventListener("input", applyAppearance);
        fontInput.addEventListener("change", applyAppearance);
        headerStartInput.addEventListener("input", applyAppearance);
        headerEndInput.addEventListener("input", applyAppearance);
        headerTextInput.addEventListener("input", applyAppearance);
        settingsHeaderStartInput.addEventListener("input", applyAppearance);
        settingsHeaderEndInput.addEventListener("input", applyAppearance);
        settingsSidebarInput.addEventListener("input", applyAppearance);
        settingsBodyInput.addEventListener("input", applyAppearance);
        settingsTextInput.addEventListener("input", applyAppearance);
        settingsSubtextInput.addEventListener("input", applyAppearance);
        settingsCardBorderInput.addEventListener("input", applyAppearance);
        settingsCardBgInput.addEventListener("input", applyAppearance);
        selectBgInput.addEventListener("input", applyAppearance);
        selectTextInput.addEventListener("input", applyAppearance);
        inputBgInput.addEventListener("input", applyAppearance);
        inputTextInput.addEventListener("input", applyAppearance);
        espValueTextColorInput.addEventListener("input", applyAppearance);
        scaleInput.addEventListener("input", applyAppearance);
        radiusInput.addEventListener("input", applyAppearance);
        blurInput.addEventListener("input", applyAppearance);
        hoverShiftInput.addEventListener("input", applyAppearance);
        displayModeButtons.forEach((btn) => {
            btn.addEventListener("click", () => {
                setDisplayMode(btn.dataset.displayMode || "merged");
                saveSettings();
            });
        });
        searchAutofocusInput.addEventListener("change", () => {
            state.searchAutofocus = searchAutofocusInput.checked;
        });
        function resetModuleTabPositions() {
            state.looseInitialized = false;
            state.loosePositions = { topbar: { x: 12, y: 12 } };
            state.loosePanelPositions = {};
            setDisplayMode(state.displayMode);
        }

        function resetAppearanceSettings() {
            accentInput.value = "#ff3d3d";
            shellBgStartInput.value = "#ff3d3d";
            shellBgEndInput.value = "#000000";
            topbarColorInput.value = "#ff4a4a";
            iconColorInput.value = "#ffdada";
            outlineColorInput.value = "#ff5b5b";
            panelCountTextInput.value = "#ffd9d9";
            panelCountBorderInput.value = "#ff6464";
            panelCountBgInput.value = "#1a1a1e";
            borderInput.value = "#ff6f6f";
            textInput.value = "#d6d6df";
            opacityInput.value = "45";
            sliderColorInput.value = "#ff6b6b";
            checkmarkColorInput.value = "#ff6b6b";
            selectBgInput.value = "#17171f";
            selectTextInput.value = "#ffe5e5";
            inputBgInput.value = "#17171f";
            inputTextInput.value = "#ffe5e5";
            mutedTextInput.value = "#9b9bab";
            accentSoftInput.value = "#ffbdbd";
            searchTextInput.value = "#ffe6e6";
            fontInput.value = "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif";
            headerStartInput.value = "#ff4a4a";
            headerEndInput.value = "#3c1212";
            headerTextInput.value = "#ffffff";
            settingsHeaderStartInput.value = "#ff3d3d";
            settingsHeaderEndInput.value = "#2d0c0c";
            settingsSidebarInput.value = "#181820";
            settingsBodyInput.value = "#121216";
            settingsTextInput.value = "#ffe5e5";
            settingsSubtextInput.value = "#c2c2ce";
            settingsCardBorderInput.value = "#ffffff";
            settingsCardBgInput.value = "#ffffff";
            espValueTextColorInput.value = "#ffffff";
            searchAutofocusInput.checked = true;
            state.searchAutofocus = true;
            state.globalPreset = "default";
            scaleInput.value = "100";
            radiusInput.value = "14";
            blurInput.value = "10";
            hoverShiftInput.value = "2";
            state.collapsedPanels = {};
            for (const panelName of panelByName.keys()) {
                setPanelCollapsed(panelName, false);
            }
            syncCollapseButtons();
            setDisplayMode("loose");
            const themeTargets = [root.style, configBackdrop.style];
            const removeThemeVar = (name) => {
                for (const target of themeTargets) target.removeProperty(name);
            };
            removeThemeVar("--zyx-border");
            removeThemeVar("--zyx-text");
            removeThemeVar("--zyx-font");
            removeThemeVar("--zyx-muted");
            removeThemeVar("--zyx-accent-soft");
            removeThemeVar("--zyx-search-text");
            removeThemeVar("--zyx-topbar-bg-start");
            removeThemeVar("--zyx-topbar-bg-end");
            removeThemeVar("--zyx-module-hover-bg");
            removeThemeVar("--zyx-module-hover-border");
            removeThemeVar("--zyx-module-active-start");
            removeThemeVar("--zyx-module-active-end");
            removeThemeVar("--zyx-module-active-border");
            removeThemeVar("--zyx-icon-color");
            removeThemeVar("--zyx-outline-color");
            removeThemeVar("--zyx-panel-count-text");
            removeThemeVar("--zyx-panel-count-border");
            removeThemeVar("--zyx-panel-count-bg");
            removeThemeVar("--zyx-header-bg-start");
            removeThemeVar("--zyx-header-bg-end");
            removeThemeVar("--zyx-header-text");
            removeThemeVar("--zyx-settings-header-start");
            removeThemeVar("--zyx-settings-header-end");
            removeThemeVar("--zyx-settings-sidebar-bg");
            removeThemeVar("--zyx-settings-body-bg");
            removeThemeVar("--zyx-settings-text");
            removeThemeVar("--zyx-settings-subtext");
            removeThemeVar("--zyx-settings-card-border");
            removeThemeVar("--zyx-settings-card-bg");
            removeThemeVar("--zyx-slider-color");
            removeThemeVar("--zyx-checkmark-color");
            removeThemeVar("--zyx-select-bg");
            removeThemeVar("--zyx-select-text");
            removeThemeVar("--zyx-radius-xl");
            removeThemeVar("--zyx-radius-lg");
            removeThemeVar("--zyx-radius-md");
            removeThemeVar("--zyx-hover-shift");
            removeThemeVar("--zyx-shell-blur");
            removeThemeVar("--zyx-btn-bg");
            removeThemeVar("--zyx-btn-hover-bg");
            shell.style.background = "";
            shell.style.transform = "";
            shell.style.backdropFilter = "";
        }

        settingsResetPositionsBtn.addEventListener("click", () => {
            resetModuleTabPositions();
            saveSettings();
        });

        settingsResetBtn.addEventListener("click", () => {
            resetAppearanceSettings();
            resetModuleTabPositions();
            saveSettings();
        });

        settingsResetAllBtn.addEventListener("click", () => {
            resetAppearanceSettings();
            resetModuleTabPositions();
            state.hiddenCategories = {};
            state.globalPreset = "default";
            state.enabledModules = new Set();
            for (const [moduleName, moduleInstance] of state.modules.entries()) {
                if (!moduleInstance?.enabled) continue;
                try { moduleInstance.disable(); } catch (_) { }
                const item = state.moduleItems.get(moduleName);
                item?.classList.remove("active");
            }
            state.moduleConfig = new Map();
            for (const item of state.moduleItems.values()) {
                const moduleName = item.dataset.module;
                if (!moduleName) continue;
                setBindLabel(item, moduleName);
            }
            setCurrentBindText(null);
            state.listeningForBind = null;
            setBindButtonText("Set keybind");
            applySearchFilter();
            saveSettings();
            try { closeConfig(); } catch (_) { }
        });

        function saveSettings(showFeedback = false) {
            try {
                const payload = collectSettings();
                localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
                if (showFeedback) {
                    settingsSaveBtn.textContent = "Saved";
                    setTimeout(() => {
                        settingsSaveBtn.textContent = "Save";
                    }, 850);
                }
            } catch (error) {
                console.error(error);
                if (showFeedback) {
                    settingsSaveBtn.textContent = "Save failed";
                    setTimeout(() => {
                        settingsSaveBtn.textContent = "Save";
                    }, 1200);
                }
            }
        }

        settingsSaveBtn.addEventListener("click", () => {
            saveSettings(true);
        });

        settingsCloseBtn.addEventListener("click", () => {
            closeConfig();
        });
        configResetBtn?.addEventListener("click", () => {
            if (!openConfigModule) return;
            const moduleName = openConfigModule;
            resetModuleConfig(moduleName);
            if (moduleName === ABILITY_HUD_MODULE_NAME) {
                applyAbilityHudLiveConfig({ cfg: moduleCfg(moduleName) });
                requestAbilityHudRender();
            } else if (moduleName === "Upgrade HUD") {
                hardRefreshUpgradeHud(moduleCfg(moduleName));
            } else if (moduleName === "Building HUD") {
                hardRefreshLavaBuildingHud(moduleCfg(moduleName));
            }
            openConfig(moduleName);
        });
        configCloseBtn.addEventListener("click", () => closeConfig());
        settingsTopCloseBtn.addEventListener("click", () => closeConfig());

        const generalPanels = document.createElement("div");
        generalPanels.className = "zyrox-panels";
        for (const generalGroup of MENU_LAYOUT.general.groups) {
            generalPanels.appendChild(buildPanel(generalGroup.name, generalGroup.modules));
        }
        generalSection.appendChild(generalPanels);

        const gamemodePanels = document.createElement("div");
        gamemodePanels.className = "zyrox-panels";
        for (const gm of MENU_LAYOUT.gamemodeSpecific.groups) {
            gamemodePanels.appendChild(buildPanel(gm.name, gm.modules));
        }
        gamemodeSection.appendChild(gamemodePanels);

        for (const [panelName] of panelByName.entries()) {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "zyrox-collapse-btn";
            btn.textContent = panelName;
            btn.addEventListener("click", () => {
                const nextCollapsed = !state.collapsedPanels[panelName];
                setPanelCollapsed(panelName, nextCollapsed);
                btn.classList.toggle("inactive", nextCollapsed);
            });
            collapseRow.appendChild(btn);
        }

        function renderHiddenCategorySettings() {
            if (!hiddenCategoriesList) return;
            hiddenCategoriesList.innerHTML = "";
            for (const panelName of panelByName.keys()) {
                const btn = document.createElement("button");
                btn.type = "button";
                btn.className = "zyrox-hidden-category-btn";
                btn.dataset.panelName = panelName;
                btn.textContent = panelName;
                btn.classList.toggle("is-hidden", isPanelHidden(panelName));
                btn.title = isPanelHidden(panelName) ? "Currently hidden. Click to show." : "Currently visible. Click to hide.";
                btn.addEventListener("click", () => {
                    const nextHidden = !isPanelHidden(panelName);
                    setPanelHidden(panelName, nextHidden);
                    btn.classList.toggle("is-hidden", nextHidden);
                    btn.title = nextHidden ? "Currently hidden. Click to show." : "Currently visible. Click to hide.";
                    saveSettings();
                });
                hiddenCategoriesList.appendChild(btn);
            }
        }

        renderHiddenCategorySettings();

        shell.appendChild(topbar);
        shell.appendChild(generalSection);
        shell.appendChild(gamemodeSection);
        shell.appendChild(footer);
        shell.appendChild(resizeHandle);

        root.appendChild(shell);

        document.head.appendChild(style);
        document.body.appendChild(root);
        document.body.appendChild(configBackdrop);

        let pendingEnabledModules = [];
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) {
                const saved = JSON.parse(raw);
                if (saved && typeof saved === "object") {
                    if (saved.toggleKey) CONFIG.toggleKey = saved.toggleKey;
                    if (typeof saved.globalPreset === "string") state.globalPreset = normalizePopupPresetName(saved.globalPreset);
                    if (typeof saved.searchAutofocus === "boolean") {
                        state.searchAutofocus = saved.searchAutofocus;
                        searchAutofocusInput.checked = saved.searchAutofocus;
                    }
                    const assign = (input, key) => {
                        if (saved[key] !== undefined && input) input.value = String(saved[key]);
                    };
                    assign(accentInput, "accent");
                    assign(shellBgStartInput, "shellBgStart");
                    assign(shellBgEndInput, "shellBgEnd");
                    assign(topbarColorInput, "topbarColor");
                    assign(iconColorInput, "iconColor");
                    assign(outlineColorInput, "outlineColor");
                    assign(panelCountTextInput, "panelCountText");
                    assign(panelCountBorderInput, "panelCountBorder");
                    assign(panelCountBgInput, "panelCountBg");
                    assign(borderInput, "border");
                    assign(textInput, "text");
                    assign(opacityInput, "opacity");
                    assign(sliderColorInput, "sliderColor");
                    assign(checkmarkColorInput, "checkmarkColor");
                    assign(selectBgInput, "selectBg");
                    assign(selectTextInput, "selectText");
                    assign(inputBgInput, "inputBg");
                    assign(inputTextInput, "inputText");
                    assign(mutedTextInput, "mutedText");
                    assign(accentSoftInput, "accentSoft");
                    assign(searchTextInput, "searchText");
                    assign(fontInput, "font");
                    assign(headerStartInput, "headerStart");
                    assign(headerEndInput, "headerEnd");
                    assign(headerTextInput, "headerText");
                    assign(settingsHeaderStartInput, "settingsHeaderStart");
                    assign(settingsHeaderEndInput, "settingsHeaderEnd");
                    assign(settingsSidebarInput, "settingsSidebar");
                    assign(settingsBodyInput, "settingsBody");
                    assign(settingsTextInput, "settingsText");
                    assign(settingsSubtextInput, "settingsSubtext");
                    assign(settingsCardBorderInput, "settingsCardBorder");
                    assign(settingsCardBgInput, "settingsCardBg");
                    assign(espValueTextColorInput, "espValueTextColor");
                    assign(scaleInput, "scale");
                    assign(radiusInput, "radius");
                    assign(blurInput, "blur");
                    assign(hoverShiftInput, "hoverShift");
                    state.displayMode = normalizeDisplayMode(saved.displayMode);
                    if (typeof saved.looseInitialized === "boolean") state.looseInitialized = saved.looseInitialized;
                    if (saved.loosePositions && typeof saved.loosePositions === "object") {
                        state.loosePositions = {
                            topbar: normalizeLoosePoint(saved.loosePositions.topbar, state.loosePositions.topbar.x, state.loosePositions.topbar.y),
                        };
                    }
                    if (saved.loosePanelPositions && typeof saved.loosePanelPositions === "object") {
                        const normalizedPanelPositions = {};
                        for (const [panelName, panelPos] of Object.entries(saved.loosePanelPositions)) {
                            normalizedPanelPositions[panelName] = normalizeLoosePoint(panelPos, 16, 68);
                        }
                        state.loosePanelPositions = normalizedPanelPositions;
                    }
                    if (saved.collapsedPanels && typeof saved.collapsedPanels === "object") {
                        state.collapsedPanels = saved.collapsedPanels;
                        if (saved.collapsedPanels["Quality of life"] !== undefined && saved.collapsedPanels.Qol === undefined) {
                            state.collapsedPanels.Qol = !!saved.collapsedPanels["Quality of life"];
                        }
                    }
                    if (saved.hiddenCategories && typeof saved.hiddenCategories === "object") {
                        state.hiddenCategories = saved.hiddenCategories;
                        if (saved.hiddenCategories["Quality of life"] !== undefined && saved.hiddenCategories.Qol === undefined) {
                            state.hiddenCategories.Qol = !!saved.hiddenCategories["Quality of life"];
                        }
                    }
                    if (saved.hiddenCategories && typeof saved.hiddenCategories === "object") {
                        state.hiddenCategories = saved.hiddenCategories;
                    }
                    const savedModuleConfig = Array.isArray(saved.moduleConfig)
                        ? saved.moduleConfig
                        : (Array.isArray(saved.moduleSettings) ? saved.moduleSettings : null);
                    if (savedModuleConfig) {
                        const migratedModuleConfig = savedModuleConfig.map(([name, cfg]) => {
                            const nextName = name === LEGACY_ANIMATION_SKIP_MODULE_NAME ? ANIMATION_SKIP_MODULE_NAME : name;
                            const nextCfg = (cfg && typeof cfg === "object") ? { ...cfg } : cfg;
                            if (nextName === ABILITY_HUD_MODULE_NAME && nextCfg && typeof nextCfg === "object") {
                                delete nextCfg.abilityHudEnabled; delete nextCfg.abilityHudPositionX; delete nextCfg.abilityHudPositionY; delete nextCfg.abilityHudZIndex; delete nextCfg.abilityHudOpacity;
                            }
                            return [nextName, nextCfg];
                        });
                        state.moduleConfig = new Map(migratedModuleConfig);
                    }
                    if (Array.isArray(saved.enabledModules)) {
                        pendingEnabledModules = saved.enabledModules
                            .filter((name) => typeof name === "string")
                            .map((name) => (name === LEGACY_ANIMATION_SKIP_MODULE_NAME ? ANIMATION_SKIP_MODULE_NAME : name));
                    }
                    settingsMenuKeyBtn.textContent = `Menu Key: ${CONFIG.toggleKey}`;
                    setFooterText();
                }
            }
        } catch (_) { }

        for (const panelName of panelByName.keys()) {
            setPanelCollapsed(panelName, !!state.collapsedPanels[panelName]);
        }
        renderHiddenCategorySettings();
        syncCollapseButtons();
        applyAppearance();
        setDisplayMode(state.displayMode);
        applySearchFilter();


        function hydrateHudConfigsFromStorage() {
            const hudModules = ["Upgrade HUD", "Building HUD", ABILITY_HUD_MODULE_NAME];
            for (const moduleName of hudModules) {
                const cfg = moduleCfg(moduleName);
                if (!cfg || typeof cfg !== "object") continue;
                let didPatch = false;
                if (moduleName === "Upgrade HUD") {
                    const normalized = readUpgradeHudConfig();
                    for (const [k, v] of Object.entries(normalized)) { if (cfg[k] === undefined) { cfg[k] = v; didPatch = true; } }
                } else if (moduleName === "Building HUD") {
                    const normalized = readBuildingHudConfig();
                    for (const [k, v] of Object.entries(normalized)) { if (cfg[k] === undefined) { cfg[k] = v; didPatch = true; } }
                } else {
                    const normalized = getAbilityHudConfigFromRaw(cfg);
                    for (const [k, v] of Object.entries(normalized)) { if (cfg[k] === undefined) { cfg[k] = v; didPatch = true; } }
                    const pos = normalizeHudPosition(cfg.hudPosition, null);
                    if (cfg.hudPosition === undefined && pos) { cfg.hudPosition = pos; didPatch = true; }
                }
                if (didPatch && typeof saveSettings === "function") saveSettings();
            }
        }
        hydrateHudConfigsFromStorage();
        for (const moduleName of pendingEnabledModules) {
            const moduleInstance = state.modules.get(moduleName);
            if (!moduleInstance || moduleInstance.enabled) continue;
            toggleModule(moduleName);
        }

        const isTypingTarget = (target) => {
            if (!(target instanceof Element)) return false;
            return Boolean(target.closest("input, textarea, select, [contenteditable='true']"));
        };

        function setVisible(nextVisible) {
            state.visible = nextVisible;
            root.classList.toggle("zyrox-hidden", !nextVisible);
            if (!nextVisible) closeConfig();
            if (nextVisible && state.searchAutofocus) {
                requestAnimationFrame(() => {
                    searchInput.focus();
                    if (searchInput.value === CONFIG.toggleKey) {
                        searchInput.value = "";
                        state.searchQuery = "";
                        applySearchFilter();

                    }
                });
            }
        }

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                if (!configBackdrop.classList.contains("hidden")) {
                    event.preventDefault();
                    closeConfig();
                    return;
                }
            }

            if (state.listeningForMenuBind) {
                event.preventDefault();
                CONFIG.toggleKey = event.key;
                settingsMenuKeyBtn.textContent = `Menu Key: ${CONFIG.toggleKey}`;
                setFooterText();
                state.listeningForMenuBind = false;
                saveSettings();
                return;
            }

            if (state.listeningForBind && openConfigModule === state.listeningForBind) {
                event.preventDefault();
                const cfg = moduleCfg(openConfigModule);
                cfg.keybind = event.key;
                const item = state.moduleItems.get(openConfigModule);
                if (item) setBindLabel(item, openConfigModule);
                setCurrentBindText(cfg.keybind);
                setBindButtonText("Set keybind");
                state.listeningForBind = null;
                saveSettings();
                return;
            }

            if (event.key === CONFIG.toggleKey) {
                if (isTypingTarget(event.target)) return;
                event.preventDefault();
                setVisible(!state.visible);
                return;
            }

            if (isTypingTarget(event.target)) return;

            if (state.enabledModules.has(CAMERA_ZOOM_MODULE_NAME)) {
                const cfg = moduleCfg(CAMERA_ZOOM_MODULE_NAME);
                let nextZoom = Number(cfg.zoom ?? CAMERA_ZOOM_DEFAULT) || CAMERA_ZOOM_DEFAULT;
                if (event.key === "[") {
                    event.preventDefault();
                    nextZoom = clampCameraZoom(nextZoom - CAMERA_ZOOM_STEP);
                } else if (event.key === "]") {
                    event.preventDefault();
                    nextZoom = clampCameraZoom(nextZoom + CAMERA_ZOOM_STEP);
                } else if (event.key === "\\") {
                    event.preventDefault();
                    nextZoom = CAMERA_ZOOM_DEFAULT;
                }
                if (nextZoom !== Number(cfg.zoom ?? CAMERA_ZOOM_DEFAULT)) {
                    cfg.zoom = nextZoom;
                    showCameraZoomToast(nextZoom);
                    saveSettings();
                }
            }

            for (const [moduleName, cfg] of ensureModuleConfigStore()) {
                if (cfg.keybind && cfg.keybind === event.key) {
                    toggleModule(moduleName);
                }
            }
        });

        // Intentionally no backdrop click-to-close; menus close only via explicit close buttons.

        topbar.addEventListener("mousedown", (event) => {
            const interactiveTarget = event.target instanceof Element
                ? event.target.closest("input, button")
                : null;
            if (interactiveTarget) return;

            const rootBox = root.getBoundingClientRect();
            if (state.displayMode === "loose") {
                const box = topbar.getBoundingClientRect();
                const shellRect = shell.getBoundingClientRect();
                const scale = getShellScale();
                dragState = {
                    mode: "topbar",
                    offsetX: event.clientX - box.left,
                    offsetY: event.clientY - box.top,
                    shellLeft: shellRect.left,
                    shellTop: shellRect.top,
                    scale,
                };
            } else {
                dragState = {
                    mode: "root",
                    offsetX: event.clientX - rootBox.left,
                    offsetY: event.clientY - rootBox.top,
                };
            }
            event.preventDefault();
        });

        panelByName.forEach((panel, panelName) => {
            const header = panel.querySelector(".zyrox-panel-header");
            header.addEventListener("mousedown", (event) => {
                if (state.displayMode !== "loose") return;
                const box = panel.getBoundingClientRect();
                const shellRect = shell.getBoundingClientRect();
                const scale = getShellScale();
                panelDragState.panelName = panelName;
                panelDragState.offsetX = event.clientX - box.left;
                panelDragState.offsetY = event.clientY - box.top;
                panelDragState.shellLeft = shellRect.left;
                panelDragState.shellTop = shellRect.top;
                panelDragState.scale = scale;
                event.preventDefault();
                event.stopPropagation();
            });
        });

        document.addEventListener("mousemove", (event) => {
            if (dragState?.mode === "root") {
                const clamped = clampToViewport(event.clientX - dragState.offsetX, event.clientY - dragState.offsetY, root);
                root.style.left = `${clamped.x}px`;
                root.style.top = `${clamped.y}px`;
                hasPositionChanges = true;
            }

            if (dragState?.mode === "topbar") {
                const scale = dragState.scale || 1;
                const unclampedX = (event.clientX - dragState.offsetX - dragState.shellLeft) / scale;
                const unclampedY = (event.clientY - dragState.offsetY - dragState.shellTop) / scale;
                const clamped = clampLoosePosition(unclampedX, unclampedY, topbar, scale, {
                    left: dragState.shellLeft,
                    top: dragState.shellTop,
                });
                state.loosePositions.topbar = clamped;
                topbar.style.left = `${clamped.x}px`;
                topbar.style.top = `${clamped.y}px`;
                hasPositionChanges = true;
            }

            if (panelDragState.panelName) {
                const panel = panelByName.get(panelDragState.panelName);
                if (panel) {
                    const scale = panelDragState.scale || 1;
                    const unclampedX = (event.clientX - panelDragState.offsetX - panelDragState.shellLeft) / scale;
                    const unclampedY = (event.clientY - panelDragState.offsetY - panelDragState.shellTop) / scale;
                    const clamped = clampLoosePosition(unclampedX, unclampedY, panel, scale, {
                        left: panelDragState.shellLeft,
                        top: panelDragState.shellTop,
                    });
                    state.loosePanelPositions[panelDragState.panelName] = clamped;
                    panel.style.left = `${clamped.x}px`;
                    panel.style.top = `${clamped.y}px`;
                    hasPositionChanges = true;
                }
            }
        });

        document.addEventListener("mouseup", () => {
            const shouldSave = hasPositionChanges || hasSizeChanges;
            dragState = null;
            resizeState = null;
            panelDragState.panelName = null;
            panelDragState.shellLeft = 0;
            panelDragState.shellTop = 0;
            panelDragState.scale = 1;
            hasPositionChanges = false;
            hasSizeChanges = false;
            if (shouldSave) saveSettings();
        });

        resizeHandle.addEventListener("mousedown", (event) => {
            if (state.displayMode === "loose") return;
            resizeState = {
                startX: event.clientX,
                startY: event.clientY,
                startWidth: state.shellWidth,
                startHeight: state.shellHeight,
            };
            event.preventDefault();
            event.stopPropagation();
        });

        document.addEventListener("mousemove", (event) => {
            if (!resizeState || state.displayMode === "loose") return;

            const width = Math.max(760, resizeState.startWidth + (event.clientX - resizeState.startX));
            const height = Math.max(420, resizeState.startHeight + (event.clientY - resizeState.startY));
            state.shellWidth = width;
            state.shellHeight = height;
            shell.style.width = `${width}px`;
            shell.style.height = `${height}px`;
            hasSizeChanges = true;
        });

        // Theme category switching functionality
        const themeCategories = [...settingsMenu.querySelectorAll(".zyrox-theme-category")];
        const themeSections = [...settingsMenu.querySelectorAll(".zyrox-theme-section")];

        themeCategories.forEach((category) => {
            category.addEventListener("click", () => {
                const targetCategory = category.dataset.category;

                // Update active category
                themeCategories.forEach((cat) => cat.classList.toggle("active", cat === category));

                // Show corresponding section
                themeSections.forEach((section) => {
                    section.classList.toggle("active", section.dataset.section === targetCategory);
                });
            });
        });

    } // end initUi

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initUi, { once: true });
    } else {
        initUi();
    }
})();
