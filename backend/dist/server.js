// src/server.ts
import { join as join2 } from "node:path";

// src/app.ts
import cors from "cors";
import express from "express";
import multer from "multer";

// ../shared/auth-service.ts
var AuthError = class extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = "AuthError";
  }
  code;
};
var EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
var CODE_TTL_MS = 10 * 60 * 1e3;
var MAX_CODE_ATTEMPTS = 5;
var USERS_KEY = "ns.users";
function validatePassword(password) {
  if (password.length < 8) return "Use at least 8 characters.";
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) return "Mix letters and numbers.";
  return null;
}
var encoder = new TextEncoder();
var toHex = (buffer) => Array.from(buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
var fromHex = (hex) => new Uint8Array(hex.match(/../g).map((pair) => parseInt(pair, 16)));
var AuthService = class {
  constructor(store, mailer, options = {}) {
    this.store = store;
    this.mailer = mailer;
    this.iterations = options.iterations ?? 12e4;
    this.now = options.now ?? Date.now;
  }
  store;
  mailer;
  iterations;
  now;
  async register(displayName, email, password) {
    const name = displayName.trim();
    const address = this.normalize(email);
    if (!name) throw new AuthError("NAME_REQUIRED", "Enter your name.");
    if (!EMAIL_PATTERN.test(address)) throw new AuthError("INVALID_EMAIL", "Enter a valid email address.");
    const weakness = validatePassword(password);
    if (weakness) throw new AuthError("WEAK_PASSWORD", weakness);
    const users = this.loadUsers();
    if (users[address]) throw new AuthError("EMAIL_TAKEN", "An account with this email already exists. Sign in instead.");
    const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const user = {
      id: crypto.randomUUID(),
      email: address,
      displayName: name,
      salt,
      passwordHash: await this.hashPassword(password, salt),
      verified: false,
      createdAt: this.now(),
      pendingCode: null
    };
    users[address] = user;
    await this.issueCode(users, user, "verify");
  }
  async resendVerification(email) {
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (user && !user.verified) await this.issueCode(users, user, "verify");
  }
  async verifyEmail(email, code) {
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (!user) throw new AuthError("INVALID_CODE", "That code is not valid.");
    await this.consumeCode(users, user, "verify", code);
    user.verified = true;
    this.saveUsers(users);
    return this.startSession(user);
  }
  async login(email, password) {
    const user = this.loadUsers()[this.normalize(email)];
    const valid = user ? await this.hashPassword(password, user.salt) === user.passwordHash : false;
    if (!user || !valid) throw new AuthError("INVALID_CREDENTIALS", "Email or password is incorrect.");
    if (!user.verified) throw new AuthError("EMAIL_NOT_VERIFIED", "Verify your email before signing in.");
    return this.startSession(user);
  }
  /** Always resolves, so the response never reveals whether an account exists. */
  async requestPasswordReset(email) {
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (user) await this.issueCode(users, user, "reset");
  }
  async resetPassword(email, code, newPassword) {
    const weakness = validatePassword(newPassword);
    if (weakness) throw new AuthError("WEAK_PASSWORD", weakness);
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (!user) throw new AuthError("INVALID_CODE", "That code is not valid.");
    await this.consumeCode(users, user, "reset", code);
    user.salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    user.passwordHash = await this.hashPassword(newPassword, user.salt);
    user.verified = true;
    this.saveUsers(users);
  }
  findUser(userId) {
    return Object.values(this.loadUsers()).find((user) => user.id === userId);
  }
  startSession(user) {
    return { userId: user.id, email: user.email, displayName: user.displayName, issuedAt: this.now() };
  }
  async issueCode(users, user, purpose) {
    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1e6).padStart(6, "0");
    user.pendingCode = { hash: await this.sha256(`${purpose}:${code}`), purpose, expiresAt: this.now() + CODE_TTL_MS, attempts: 0 };
    this.saveUsers(users);
    const subject = purpose === "verify" ? "Verify your Nightshade account" : "Reset your Nightshade password";
    const body = purpose === "verify" ? `Hi ${user.displayName}, your verification code is ${code}. It expires in 10 minutes.` : `Your password reset code is ${code}. It expires in 10 minutes. Ignore this email if you did not ask for it.`;
    await this.mailer.send({ to: user.email, subject, body, code, purpose, sentAt: this.now() });
  }
  async consumeCode(users, user, purpose, code) {
    const pending = user.pendingCode;
    if (!pending || pending.purpose !== purpose) throw new AuthError("INVALID_CODE", "That code is not valid. Request a new one.");
    if (this.now() > pending.expiresAt) {
      user.pendingCode = null;
      this.saveUsers(users);
      throw new AuthError("CODE_EXPIRED", "That code has expired. Request a new one.");
    }
    if (pending.attempts >= MAX_CODE_ATTEMPTS) throw new AuthError("TOO_MANY_ATTEMPTS", "Too many attempts. Request a new code.");
    if (await this.sha256(`${purpose}:${code.trim()}`) !== pending.hash) {
      pending.attempts++;
      this.saveUsers(users);
      const left = MAX_CODE_ATTEMPTS - pending.attempts;
      throw new AuthError("INVALID_CODE", `That code is not valid. ${left} attempt${left === 1 ? "" : "s"} left.`);
    }
    user.pendingCode = null;
  }
  async hashPassword(password, saltHex) {
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: this.iterations },
      key,
      256
    );
    return toHex(bits);
  }
  async sha256(text) {
    return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
  }
  normalize(email) {
    return email.trim().toLowerCase();
  }
  loadUsers() {
    try {
      return JSON.parse(this.store.get(USERS_KEY) ?? "{}");
    } catch {
      return {};
    }
  }
  saveUsers(users) {
    this.store.set(USERS_KEY, JSON.stringify(users));
  }
};

// ../shared/linked-list.ts
var ListNode = class {
  constructor(value) {
    this.value = value;
  }
  value;
  prev = null;
  next = null;
};
var DoublyLinkedList = class {
  head = null;
  tail = null;
  length = 0;
  constructor(values = []) {
    for (const value of values) this.append(value);
  }
  get size() {
    return this.length;
  }
  get first() {
    return this.head;
  }
  get last() {
    return this.tail;
  }
  // Pointer primitives: the only methods allowed to rewire prev/next.
  linkLast(node) {
    node.prev = this.tail;
    node.next = null;
    if (this.tail) this.tail.next = node;
    else this.head = node;
    this.tail = node;
    this.length++;
  }
  linkBefore(node, ref) {
    node.prev = ref.prev;
    node.next = ref;
    if (ref.prev) ref.prev.next = node;
    else this.head = node;
    ref.prev = node;
    this.length++;
  }
  unlink(node) {
    if (node.prev) node.prev.next = node.next;
    else this.head = node.next;
    if (node.next) node.next.prev = node.prev;
    else this.tail = node.prev;
    node.prev = node.next = null;
    this.length--;
    return node.value;
  }
  assertIndex(index, max) {
    if (!Number.isInteger(index) || index < 0 || index > max) {
      throw new RangeError(`Index ${index} out of range (size=${this.length})`);
    }
  }
  /** True while the node is still linked into this list. */
  contains(node) {
    return node === this.head || node.prev !== null && node.prev.next === node;
  }
  append(value) {
    const node = new ListNode(value);
    this.linkLast(node);
    return node;
  }
  prepend(value) {
    const node = new ListNode(value);
    if (this.head) this.linkBefore(node, this.head);
    else this.linkLast(node);
    return node;
  }
  insertAt(index, value) {
    this.assertIndex(index, this.length);
    if (index === this.length) return this.append(value);
    const node = new ListNode(value);
    this.linkBefore(node, this.nodeAt(index));
    return node;
  }
  /** Walks from the closest end: O(min(i, n - i)). */
  nodeAt(index) {
    this.assertIndex(index, this.length - 1);
    let node;
    if (index < this.length / 2) {
      node = this.head;
      for (let i = 0; i < index; i++) node = node.next;
    } else {
      node = this.tail;
      for (let i = this.length - 1; i > index; i--) node = node.prev;
    }
    return node;
  }
  get(index) {
    return this.nodeAt(index).value;
  }
  removeAt(index) {
    return this.unlink(this.nodeAt(index));
  }
  removeNode(node) {
    if (!this.contains(node)) throw new Error("Node does not belong to this list");
    return this.unlink(node);
  }
  removeWhere(predicate) {
    let removed = 0;
    let node = this.head;
    while (node) {
      const following = node.next;
      if (predicate(node.value)) {
        this.unlink(node);
        removed++;
      }
      node = following;
    }
    return removed;
  }
  findNode(predicate) {
    for (let node = this.head; node; node = node.next) if (predicate(node.value)) return node;
    return null;
  }
  indexOf(predicate) {
    let index = 0;
    for (let node = this.head; node; node = node.next, index++) if (predicate(node.value)) return index;
    return -1;
  }
  indexOfNode(target) {
    let index = 0;
    for (let node = this.head; node; node = node.next, index++) if (node === target) return index;
    return -1;
  }
  /**
   * Relinks the node at `from` so it ends up at `to` (same semantics as
   * `arr.splice(to, 0, arr.splice(from, 1)[0])`). No node is created or copied,
   * so external pointers to it (e.g. the playback cursor) stay valid.
   */
  move(from, to) {
    this.assertIndex(from, this.length - 1);
    this.assertIndex(to, this.length - 1);
    if (from === to) return;
    const node = this.nodeAt(from);
    this.unlink(node);
    if (to === this.length) this.linkLast(node);
    else this.linkBefore(node, this.nodeAt(to));
  }
  clear() {
    let node = this.head;
    while (node) {
      const following = node.next;
      node.prev = node.next = null;
      node = following;
    }
    this.head = this.tail = null;
    this.length = 0;
  }
  toArray() {
    return [...this];
  }
  *[Symbol.iterator]() {
    for (let node = this.head; node; node = node.next) yield node.value;
  }
  *reversed() {
    for (let node = this.tail; node; node = node.prev) yield node.value;
  }
  checkIntegrity() {
    if (this.length === 0) {
      if (this.head || this.tail) throw new Error("Empty list must have no head/tail");
      return;
    }
    if (!this.head || !this.tail) throw new Error("Non-empty list needs head and tail");
    if (this.head.prev !== null) throw new Error("head.prev must be null");
    if (this.tail.next !== null) throw new Error("tail.next must be null");
    let count = 0;
    let last = null;
    for (let node = this.head; node; node = node.next) {
      if (node.prev !== last) throw new Error(`Broken back-pointer at position ${count}`);
      last = node;
      if (++count > this.length) throw new Error("Cycle detected or size too small");
    }
    if (last !== this.tail) throw new Error("Forward walk must end at tail");
    if (count !== this.length) throw new Error(`Size mismatch: counted ${count}, stored ${this.length}`);
  }
};

// ../shared/types.ts
var SUPPORTED_AUDIO_EXTENSIONS = [".mp3", ".ogg", ".wav", ".flac", ".m4a", ".aac", ".webm"];
var SUPPORTED_AUDIO_MIME_TYPES = [
  "audio/mpeg",
  "audio/mp3",
  "audio/ogg",
  "audio/wav",
  "audio/x-wav",
  "audio/flac",
  "audio/mp4",
  "audio/x-m4a",
  "audio/aac",
  "audio/webm"
];
var OPEN_MUSIC_PROVIDERS = [
  { id: "internet-archive", label: "Internet Archive", host: "archive.org" },
  { id: "jamendo", label: "Jamendo", host: "jamendo.com" },
  { id: "free-music-archive", label: "Free Music Archive", host: "freemusicarchive.org" },
  { id: "ccmixter", label: "ccMixter", host: "ccmixter.org" },
  { id: "github", label: "GitHub", host: "githubusercontent.com" },
  { id: "wikimedia", label: "Wikimedia Commons", host: "wikimedia.org" }
];
var MUSIC_PLAYLIST_NAME = "Music";

// ../shared/library-service.ts
var Playlist = class {
  constructor(id, name, system, trackIds = [], createdAt = Date.now()) {
    this.id = id;
    this.name = name;
    this.system = system;
    this.createdAt = createdAt;
    this.tracks = new DoublyLinkedList(trackIds);
  }
  id;
  name;
  system;
  createdAt;
  tracks;
  toData() {
    return { id: this.id, name: this.name, system: this.system, trackIds: this.tracks.toArray(), createdAt: this.createdAt };
  }
};
var LibraryError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "LibraryError";
  }
};
var MAX_FILE_BYTES = 200 * 1024 * 1024;
var MAX_PLAYLIST_NAME = 60;
function parseTrackName(fileName) {
  const base = fileName.replace(/\.[^.]+$/, "").replace(/_+/g, " ").trim();
  const parts = base.split(/\s+-\s+/);
  if (parts.length >= 2) return { artist: parts[0].trim(), title: parts.slice(1).join(" - ").trim() };
  return { artist: "Unknown artist", title: base || "Untitled" };
}
function isSupportedAudio(file) {
  const name = file.name.toLowerCase();
  return SUPPORTED_AUDIO_MIME_TYPES.includes(file.type) || SUPPORTED_AUDIO_EXTENSIONS.some((extension) => name.endsWith(extension));
}
function detectProvider(url) {
  const host = url.hostname.toLowerCase();
  return OPEN_MUSIC_PROVIDERS.find((provider) => host === provider.host || host.endsWith(`.${provider.host}`))?.id ?? "other";
}
function normalizeText(text) {
  return text.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();
}
var LibraryService = class {
  constructor(userId, kv, blobs, probeDuration = async () => 0) {
    this.userId = userId;
    this.kv = kv;
    this.blobs = blobs;
    this.probeDuration = probeDuration;
    this.load();
  }
  userId;
  kv;
  blobs;
  probeDuration;
  tracks = /* @__PURE__ */ new Map();
  playlists = [];
  listeners = /* @__PURE__ */ new Set();
  objectUrls = /* @__PURE__ */ new Map();
  get storageKey() {
    return `ns.library.${this.userId}`;
  }
  get music() {
    return this.playlists[0];
  }
  onChange(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  getPlaylist(id) {
    const playlist = this.playlists.find((p) => p.id === id);
    if (!playlist) throw new LibraryError("That playlist no longer exists.");
    return playlist;
  }
  getTrack(id) {
    return this.tracks.get(id);
  }
  playlistTracks(id) {
    return this.getPlaylist(id).tracks.toArray().map((trackId) => this.tracks.get(trackId)).filter((track) => track !== void 0);
  }
  async addFiles(files, alsoAddTo) {
    const result = { added: [], rejected: [] };
    for (const file of files) {
      if (!isSupportedAudio(file)) {
        result.rejected.push({ name: file.name, reason: "Not an audio file" });
        continue;
      }
      if (file.size > MAX_FILE_BYTES) {
        result.rejected.push({ name: file.name, reason: "Larger than 200 MB" });
        continue;
      }
      const id = crypto.randomUUID();
      await this.blobs.put(id, file);
      const durationSec = await this.probeDuration(file).catch(() => 0);
      const track = {
        id,
        ...parseTrackName(file.name),
        durationSec: Number.isFinite(durationSec) ? durationSec : 0,
        source: { kind: "file", blobKey: id, fileName: file.name, mimeType: file.type || "audio/mpeg", sizeBytes: file.size },
        addedAt: Date.now()
      };
      this.registerTrack(track, alsoAddTo);
      result.added.push(track);
    }
    if (result.added.length) this.commit();
    return result;
  }
  addRemote(rawUrl, meta = {}, alsoAddTo) {
    let url;
    try {
      url = new URL(rawUrl.trim());
    } catch {
      throw new LibraryError("Enter a full link that starts with https://");
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new LibraryError("Only http and https links are supported.");
    const parsed = parseTrackName(decodeURIComponent(url.pathname.split("/").pop() ?? ""));
    const track = {
      id: crypto.randomUUID(),
      title: meta.title?.trim() || parsed.title,
      artist: meta.artist?.trim() || parsed.artist,
      durationSec: 0,
      source: { kind: "url", url: url.href, provider: detectProvider(url) },
      addedAt: Date.now()
    };
    this.registerTrack(track, alsoAddTo);
    this.commit();
    return track;
  }
  setDuration(id, durationSec) {
    const track = this.tracks.get(id);
    if (!track || !Number.isFinite(durationSec) || Math.abs(track.durationSec - durationSec) < 0.5) return;
    track.durationSec = durationSec;
    this.commit();
  }
  createPlaylist(name) {
    const playlist = new Playlist(crypto.randomUUID(), this.validateName(name), false);
    this.playlists.push(playlist);
    this.commit();
    return playlist;
  }
  renamePlaylist(id, name) {
    const playlist = this.getPlaylist(id);
    if (playlist.system) throw new LibraryError(`"${MUSIC_PLAYLIST_NAME}" holds every upload and keeps its name.`);
    playlist.name = this.validateName(name, id);
    this.commit();
  }
  deletePlaylist(id) {
    const playlist = this.getPlaylist(id);
    if (playlist.system) throw new LibraryError(`"${MUSIC_PLAYLIST_NAME}" cannot be deleted.`);
    this.playlists.splice(this.playlists.indexOf(playlist), 1);
    playlist.tracks.clear();
    this.commit();
  }
  /** Returns false when the playlist already contains the track. */
  addToPlaylist(playlistId, trackId) {
    const playlist = this.getPlaylist(playlistId);
    if (!this.tracks.has(trackId)) throw new LibraryError("That song no longer exists.");
    if (playlist.tracks.findNode((id) => id === trackId)) return false;
    playlist.tracks.append(trackId);
    this.commit();
    return true;
  }
  /** Removing from "Music" deletes the song from the whole library. */
  async removeFromPlaylist(playlistId, index) {
    const playlist = this.getPlaylist(playlistId);
    if (playlist.system) {
      await this.deleteTrack(playlist.tracks.get(index));
      return;
    }
    playlist.tracks.removeAt(index);
    this.commit();
  }
  moveInPlaylist(playlistId, from, to) {
    this.getPlaylist(playlistId).tracks.move(from, to);
    this.commit();
  }
  async deleteTrack(id) {
    const track = this.tracks.get(id);
    if (!track) return;
    for (const playlist of this.playlists) playlist.tracks.removeWhere((trackId) => trackId === id);
    this.tracks.delete(id);
    const objectUrl = this.objectUrls.get(id);
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    this.objectUrls.delete(id);
    if (track.source.kind === "file") await this.blobs.delete(track.source.blobKey);
    this.commit();
  }
  /** All query tokens must match; title prefix matches rank first. */
  search(query) {
    const tokens = normalizeText(query).split(/\s+/).filter(Boolean);
    if (!tokens.length) return [];
    const scored = [];
    for (const track of this.tracks.values()) {
      const title = normalizeText(track.title);
      const artist = normalizeText(track.artist);
      const extra = normalizeText(track.source.kind === "file" ? track.source.fileName : track.source.provider);
      const haystack = `${title} ${artist} ${extra}`;
      if (!tokens.every((token) => haystack.includes(token))) continue;
      const first = tokens[0];
      const score = title.startsWith(first) ? 0 : title.includes(first) ? 1 : artist.includes(first) ? 2 : 3;
      scored.push({ track, score });
    }
    return scored.sort((a, b) => a.score - b.score || a.track.title.localeCompare(b.track.title)).map((entry) => entry.track);
  }
  async resolveSource(track) {
    if (track.source.kind === "url") return track.source.url;
    const cached = this.objectUrls.get(track.id);
    if (cached) return cached;
    const blob = await this.blobs.get(track.source.blobKey);
    if (!blob) throw new LibraryError(`The audio for "${track.title}" is missing from this device. Upload it again.`);
    const objectUrl = URL.createObjectURL(blob);
    this.objectUrls.set(track.id, objectUrl);
    return objectUrl;
  }
  registerTrack(track, alsoAddTo) {
    this.tracks.set(track.id, track);
    this.music.tracks.append(track.id);
    if (alsoAddTo && alsoAddTo !== this.music.id) {
      const target = this.playlists.find((p) => p.id === alsoAddTo);
      target?.tracks.append(track.id);
    }
  }
  validateName(raw, ignoreId) {
    const name = raw.trim().replace(/\s+/g, " ");
    if (!name) throw new LibraryError("Give the playlist a name.");
    if (name.length > MAX_PLAYLIST_NAME) throw new LibraryError(`Keep the name under ${MAX_PLAYLIST_NAME} characters.`);
    const clash = this.playlists.some((p) => p.id !== ignoreId && p.name.toLowerCase() === name.toLowerCase());
    if (clash) throw new LibraryError(`You already have a playlist called "${name}".`);
    return name;
  }
  toData() {
    return { version: 1, tracks: [...this.tracks.values()], playlists: this.playlists.map((p) => p.toData()) };
  }
  /** Replaces everything with a snapshot (used by the client to mirror the server). */
  replaceAll(data) {
    this.tracks.clear();
    this.playlists.forEach((p) => p.tracks.clear());
    this.playlists.length = 0;
    this.apply(data);
    this.commit();
  }
  /** Adds a track created elsewhere (e.g. by the server) without generating a new id. */
  importTrack(track, alsoAddTo) {
    if (this.tracks.has(track.id)) return;
    this.registerTrack(track, alsoAddTo);
    this.commit();
  }
  load() {
    let data = null;
    try {
      const raw = this.kv.get(this.storageKey);
      data = raw ? JSON.parse(raw) : null;
    } catch {
      data = null;
    }
    this.apply(data);
  }
  apply(data) {
    for (const track of data?.tracks ?? []) this.tracks.set(track.id, track);
    for (const p of data?.playlists ?? []) {
      const ids = p.trackIds.filter((id) => this.tracks.has(id));
      this.playlists.push(new Playlist(p.id, p.name, p.system, ids, p.createdAt));
    }
    const musicIndex = this.playlists.findIndex((p) => p.system);
    if (musicIndex === -1) this.playlists.unshift(new Playlist(crypto.randomUUID(), MUSIC_PLAYLIST_NAME, true));
    else if (musicIndex > 0) this.playlists.unshift(...this.playlists.splice(musicIndex, 1));
  }
  commit() {
    this.kv.set(this.storageKey, JSON.stringify(this.toData()));
    this.listeners.forEach((listener) => listener());
  }
};

// src/infra.ts
import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import nodemailer from "nodemailer";
var FileKeyValueStore = class {
  constructor(file) {
    this.file = file;
    mkdirSync(dirname(file), { recursive: true });
    this.data = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
  }
  file;
  data;
  get(key) {
    return this.data[key] ?? null;
  }
  set(key, value) {
    this.data[key] = value;
    this.flush();
  }
  remove(key) {
    delete this.data[key];
    this.flush();
  }
  flush() {
    const temp = `${this.file}.tmp`;
    writeFileSync(temp, JSON.stringify(this.data));
    renameSync(temp, this.file);
  }
};
var SAFE_KEY = /^[A-Za-z0-9-]+$/;
var DiskBlobStore = class {
  root;
  constructor(root) {
    this.root = resolve(root);
    mkdirSync(this.root, { recursive: true });
  }
  pathFor(key) {
    if (!SAFE_KEY.test(key)) throw new Error("Invalid blob key");
    return join(this.root, key);
  }
  async put(key, blob) {
    await mkdir(this.root, { recursive: true });
    await writeFile(this.pathFor(key), Buffer.from(await blob.arrayBuffer()));
  }
  async get(key) {
    const path = this.pathFor(key);
    return existsSync(path) ? new Blob([readFileSync(path)]) : void 0;
  }
  async delete(key) {
    await rm(this.pathFor(key), { force: true });
  }
};
function createMailer(smtp) {
  if (!smtp) {
    return {
      send: (message) => console.log(`[mail] to=${message.to} subject="${message.subject}" code=${message.code}`)
    };
  }
  const transport = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.port === 465,
    auth: smtp.user ? { user: smtp.user, pass: smtp.pass } : void 0
  });
  const esc = (text) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  return {
    send: async (message) => {
      const subject = esc(message.subject);
      const body = esc(message.body);
      await transport.sendMail({
        from: smtp.from,
        to: message.to,
        subject: message.subject,
        text: message.body,
        html: `<div style="font-family:sans-serif;background:#0b0710;color:#fff;padding:24px;border-radius:12px">
          <h2 style="color:#ff8c00;margin:0 0 12px">${subject}</h2><p>${body}</p>
          <p style="font-size:28px;letter-spacing:6px;font-weight:700;color:#ff8c00">${esc(message.code)}</p></div>`
      });
    }
  };
}
var b64 = (value) => Buffer.from(value).toString("base64url");
function signToken(payload, secret, ttlSeconds) {
  const body = b64(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1e3) + ttlSeconds }));
  return `${body}.${b64(createHmac("sha256", secret).update(body).digest())}`;
}
function verifyToken(token, secret) {
  const [body, signature] = token.split(".");
  if (!body || !signature) return null;
  const expected = createHmac("sha256", secret).update(body).digest();
  const given = Buffer.from(signature, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return payload.exp * 1e3 > Date.now() ? payload : null;
  } catch {
    return null;
  }
}
function createRateLimiter(limit, windowMs) {
  const hits = /* @__PURE__ */ new Map();
  return (key) => {
    const now = Date.now();
    const entry = hits.get(key);
    if (!entry || entry.resetAt < now) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    entry.count++;
    return entry.count <= limit;
  };
}

// src/app.ts
var SESSION_TTL = 60 * 60 * 24 * 7;
var STREAM_TTL = 60 * 60 * 6;
var STATUS = {
  NAME_REQUIRED: 400,
  INVALID_EMAIL: 400,
  WEAK_PASSWORD: 400,
  INVALID_CODE: 400,
  CODE_EXPIRED: 400,
  EMAIL_TAKEN: 409,
  INVALID_CREDENTIALS: 401,
  EMAIL_NOT_VERIFIED: 403,
  TOO_MANY_ATTEMPTS: 429
};
var str = (value) => typeof value === "string" ? value : "";
var int = (value) => {
  const n = Number(value);
  if (!Number.isInteger(n)) throw new LibraryError("Expected a whole number.");
  return n;
};
function createApp(config, deps) {
  const lastMail = /* @__PURE__ */ new Map();
  const mailer = {
    send: async (message) => {
      lastMail.set(message.to, message);
      await deps.mailer.send(message);
    }
  };
  const auth = new AuthService(deps.kv, mailer, { iterations: config.passwordIterations });
  const libraries = /* @__PURE__ */ new Map();
  const libraryFor = (userId) => {
    let library2 = libraries.get(userId);
    if (!library2) {
      library2 = new LibraryService(userId, deps.kv, deps.blobs);
      libraries.set(userId, library2);
    }
    return library2;
  };
  const devCode = (email) => {
    if (!config.exposeDevCodes) return {};
    const mail = lastMail.get(email.trim().toLowerCase());
    return mail ? { devMail: { to: mail.to, subject: mail.subject, code: mail.code } } : {};
  };
  const issue = (session) => ({ token: signToken({ sub: session.userId, typ: "session" }, config.tokenSecret, SESSION_TTL), session });
  const app2 = express();
  app2.disable("x-powered-by");
  app2.use(cors({ origin: config.corsOrigins.includes("*") ? "*" : config.corsOrigins }));
  app2.use(express.json({ limit: "100kb" }));
  app2.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
  });
  const limiter = createRateLimiter(30, 6e4);
  const limited = (req, res, next) => {
    if (limiter(`${req.ip}:${req.path}`)) return next();
    res.status(429).json({ error: "TOO_MANY_REQUESTS", message: "Too many requests. Wait a minute and try again." });
  };
  const requireAuth = (req, res, next) => {
    const header = req.headers.authorization ?? "";
    const payload = header.startsWith("Bearer ") ? verifyToken(header.slice(7), config.tokenSecret) : null;
    const user = payload?.typ === "session" ? auth.findUser(payload.sub) : void 0;
    if (!user) return res.status(401).json({ error: "UNAUTHORIZED", message: "Sign in again." });
    req.session = { userId: user.id, email: user.email, displayName: user.displayName, issuedAt: Date.now() };
    next();
  };
  const library = (req) => libraryFor(req.session.userId);
  app2.get("/api/health", (_req, res) => res.json({ ok: true }));
  app2.post("/api/auth/register", limited, async (req, res) => {
    await auth.register(str(req.body.name), str(req.body.email), str(req.body.password));
    res.status(201).json({ ok: true, ...devCode(str(req.body.email)) });
  });
  app2.post("/api/auth/resend", limited, async (req, res) => {
    await auth.resendVerification(str(req.body.email));
    res.json({ ok: true, ...devCode(str(req.body.email)) });
  });
  app2.post("/api/auth/verify", limited, async (req, res) => {
    res.json(issue(await auth.verifyEmail(str(req.body.email), str(req.body.code))));
  });
  app2.post("/api/auth/login", limited, async (req, res) => {
    res.json(issue(await auth.login(str(req.body.email), str(req.body.password))));
  });
  app2.post("/api/auth/forgot", limited, async (req, res) => {
    await auth.requestPasswordReset(str(req.body.email));
    res.json({ ok: true, ...devCode(str(req.body.email)) });
  });
  app2.post("/api/auth/reset", limited, async (req, res) => {
    await auth.resetPassword(str(req.body.email), str(req.body.code), str(req.body.password));
    res.json({ ok: true });
  });
  app2.get("/api/auth/me", requireAuth, (req, res) => res.json({ session: req.session }));
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: config.maxUploadMb * 1024 * 1024, files: 50 } });
  app2.get("/api/library", requireAuth, (req, res) => res.json(library(req).toData()));
  app2.get("/api/search", requireAuth, (req, res) => res.json({ tracks: library(req).search(str(req.query.q)) }));
  app2.post("/api/tracks/upload", requireAuth, upload.array("files"), async (req, res) => {
    const files = (req.files ?? []).map(
      (f) => new File([new Uint8Array(f.buffer)], Buffer.from(f.originalname, "latin1").toString("utf8"), { type: f.mimetype })
    );
    const result = await library(req).addFiles(files, str(req.body.alsoAddTo) || void 0);
    res.status(201).json(result);
  });
  app2.post("/api/tracks/remote", requireAuth, (req, res) => {
    const track = library(req).addRemote(str(req.body.url), { title: str(req.body.title), artist: str(req.body.artist) }, str(req.body.alsoAddTo) || void 0);
    res.status(201).json({ track });
  });
  app2.patch("/api/tracks/:id", requireAuth, (req, res) => {
    library(req).setDuration(str(req.params.id), Number(req.body.durationSec));
    res.json({ ok: true });
  });
  app2.delete("/api/tracks/:id", requireAuth, async (req, res) => {
    await library(req).deleteTrack(str(req.params.id));
    res.json({ ok: true });
  });
  app2.get("/api/tracks/:id/stream-url", requireAuth, (req, res) => {
    const track = library(req).getTrack(str(req.params.id));
    if (!track) return res.status(404).json({ error: "NOT_FOUND", message: "That song no longer exists." });
    if (track.source.kind === "url") return res.json({ url: track.source.url });
    const sig = signToken({ sub: req.session.userId, tid: track.id, typ: "stream" }, config.tokenSecret, STREAM_TTL);
    res.json({ url: `${config.publicUrl}/api/stream/${track.id}?sig=${sig}` });
  });
  app2.get("/api/stream/:id", (req, res) => {
    const payload = verifyToken(str(req.query.sig), config.tokenSecret);
    if (!payload || payload.typ !== "stream" || payload.tid !== req.params.id) return res.status(403).end();
    const track = libraryFor(payload.sub).getTrack(payload.tid);
    if (!track || track.source.kind !== "file") return res.status(404).end();
    res.type(track.source.mimeType || "audio/mpeg");
    res.sendFile(deps.blobs.pathFor(track.source.blobKey), { acceptRanges: true, cacheControl: false });
  });
  app2.post("/api/playlists", requireAuth, (req, res) => res.status(201).json(library(req).createPlaylist(str(req.body.name)).toData()));
  app2.patch("/api/playlists/:id", requireAuth, (req, res) => {
    library(req).renamePlaylist(str(req.params.id), str(req.body.name));
    res.json({ ok: true });
  });
  app2.delete("/api/playlists/:id", requireAuth, (req, res) => {
    library(req).deletePlaylist(str(req.params.id));
    res.json({ ok: true });
  });
  app2.post("/api/playlists/:id/tracks", requireAuth, (req, res) => {
    res.json({ added: library(req).addToPlaylist(str(req.params.id), str(req.body.trackId)) });
  });
  app2.delete("/api/playlists/:id/tracks/:index", requireAuth, async (req, res) => {
    await library(req).removeFromPlaylist(str(req.params.id), int(req.params.index));
    res.json({ ok: true });
  });
  app2.post("/api/playlists/:id/move", requireAuth, (req, res) => {
    library(req).moveInPlaylist(str(req.params.id), int(req.body.from), int(req.body.to));
    res.json({ ok: true });
  });
  app2.use("/api", (_req, res) => res.status(404).json({ error: "NOT_FOUND", message: "Unknown endpoint." }));
  app2.use((error, _req, res, _next) => {
    if (error instanceof AuthError) return res.status(STATUS[error.code]).json({ error: error.code, message: error.message });
    if (error instanceof LibraryError || error instanceof RangeError) return res.status(400).json({ error: "BAD_REQUEST", message: error.message });
    if (error instanceof multer.MulterError) {
      const message = error.code === "LIMIT_FILE_SIZE" ? `Each file must be under ${config.maxUploadMb} MB.` : error.message;
      return res.status(413).json({ error: error.code, message });
    }
    console.error(error);
    res.status(500).json({ error: "INTERNAL", message: "Something went wrong on the server." });
  });
  return app2;
}

// src/server.ts
var env = process.env;
var port = Number(env.PORT ?? 4e3);
var dataDir = env.DATA_DIR ?? join2(process.cwd(), "data");
var tokenSecret = env.TOKEN_SECRET ?? "";
if (tokenSecret.length < 32) {
  if (env.NODE_ENV === "production") throw new Error("TOKEN_SECRET must be at least 32 characters in production.");
  console.warn("[config] TOKEN_SECRET is missing or short. Using an insecure development secret.");
}
var app = createApp(
  {
    tokenSecret: tokenSecret.length >= 32 ? tokenSecret : "dev-only-secret-change-me-0123456789abcdef",
    corsOrigins: (env.CORS_ORIGIN ?? "*").split(",").map((origin) => origin.trim()),
    publicUrl: (env.PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, ""),
    maxUploadMb: Number(env.MAX_UPLOAD_MB ?? 50),
    exposeDevCodes: env.EXPOSE_DEV_CODES === "true"
  },
  {
    kv: new FileKeyValueStore(join2(dataDir, "db.json")),
    blobs: new DiskBlobStore(join2(dataDir, "uploads")),
    mailer: createMailer(
      env.SMTP_HOST ? {
        host: env.SMTP_HOST,
        port: Number(env.SMTP_PORT ?? 587),
        user: env.SMTP_USER,
        pass: env.SMTP_PASS,
        from: env.MAIL_FROM ?? "Nightshade <no-reply@nightshade.local>"
      } : null
    )
  }
);
app.listen(port, () => console.log(`Nightshade API listening on http://localhost:${port}`));
