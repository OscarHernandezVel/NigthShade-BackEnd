import type { KeyValueStore } from './auth-service';
import { DoublyLinkedList } from './linked-list';
import {
  MUSIC_PLAYLIST_NAME,
  OPEN_MUSIC_PROVIDERS,
  SUPPORTED_AUDIO_EXTENSIONS,
  SUPPORTED_AUDIO_MIME_TYPES,
  type LibraryData,
  type OpenMusicProvider,
  type PlaylistData,
  type PlaylistId,
  type Track,
  type TrackId,
} from './types';

export interface BlobStore {
  put(key: string, blob: Blob): Promise<void>;
  get(key: string): Promise<Blob | undefined>;
  delete(key: string): Promise<void>;
}

export class MemoryBlobStore implements BlobStore {
  private readonly blobs = new Map<string, Blob>();
  async put(key: string, blob: Blob) {
    this.blobs.set(key, blob);
  }
  async get(key: string) {
    return this.blobs.get(key);
  }
  async delete(key: string) {
    this.blobs.delete(key);
  }
}

export class Playlist {
  readonly tracks: DoublyLinkedList<TrackId>;

  constructor(
    readonly id: PlaylistId,
    public name: string,
    readonly system: boolean,
    trackIds: TrackId[] = [],
    readonly createdAt = Date.now(),
  ) {
    this.tracks = new DoublyLinkedList(trackIds);
  }

  toData(): PlaylistData {
    return { id: this.id, name: this.name, system: this.system, trackIds: this.tracks.toArray(), createdAt: this.createdAt };
  }
}

export class LibraryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LibraryError';
  }
}

export interface UploadResult {
  added: Track[];
  rejected: { name: string; reason: string }[];
}

export const MAX_FILE_BYTES = 200 * 1024 * 1024;
export const MAX_PLAYLIST_NAME = 60;

export function parseTrackName(fileName: string): { title: string; artist: string } {
  const base = fileName
    .replace(/\.[^.]+$/, '')
    .replace(/_+/g, ' ')
    .trim();
  const parts = base.split(/\s+-\s+/);
  if (parts.length >= 2) return { artist: parts[0].trim(), title: parts.slice(1).join(' - ').trim() };
  return { artist: 'Unknown artist', title: base || 'Untitled' };
}

export function isSupportedAudio(file: { name: string; type: string }): boolean {
  const name = file.name.toLowerCase();
  return (
    (SUPPORTED_AUDIO_MIME_TYPES as readonly string[]).includes(file.type) ||
    SUPPORTED_AUDIO_EXTENSIONS.some((extension) => name.endsWith(extension))
  );
}

export function detectProvider(url: URL): OpenMusicProvider {
  const host = url.hostname.toLowerCase();
  return OPEN_MUSIC_PROVIDERS.find((provider) => host === provider.host || host.endsWith(`.${provider.host}`))?.id ?? 'other';
}

export function normalizeText(text: string): string {
  return text.normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase();
}

type DurationProbe = (blob: Blob) => Promise<number>;

export class LibraryService {
  readonly tracks = new Map<TrackId, Track>();
  readonly playlists: Playlist[] = [];
  private readonly listeners = new Set<() => void>();
  private readonly objectUrls = new Map<TrackId, string>();

  constructor(
    private readonly userId: string,
    private readonly kv: KeyValueStore,
    private readonly blobs: BlobStore,
    private readonly probeDuration: DurationProbe = async () => 0,
  ) {
    this.load();
  }

  private get storageKey() {
    return `ns.library.${this.userId}`;
  }

  get music(): Playlist {
    return this.playlists[0];
  }

  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  getPlaylist(id: PlaylistId): Playlist {
    const playlist = this.playlists.find((p) => p.id === id);
    if (!playlist) throw new LibraryError('That playlist no longer exists.');
    return playlist;
  }

  getTrack(id: TrackId): Track | undefined {
    return this.tracks.get(id);
  }

  playlistTracks(id: PlaylistId): Track[] {
    return this.getPlaylist(id)
      .tracks.toArray()
      .map((trackId) => this.tracks.get(trackId))
      .filter((track): track is Track => track !== undefined);
  }

  async addFiles(files: Iterable<File>, alsoAddTo?: PlaylistId): Promise<UploadResult> {
    const result: UploadResult = { added: [], rejected: [] };
    for (const file of files) {
      if (!isSupportedAudio(file)) {
        result.rejected.push({ name: file.name, reason: 'Not an audio file' });
        continue;
      }
      if (file.size > MAX_FILE_BYTES) {
        result.rejected.push({ name: file.name, reason: 'Larger than 200 MB' });
        continue;
      }
      const id = crypto.randomUUID();
      await this.blobs.put(id, file);
      const durationSec = await this.probeDuration(file).catch(() => 0);
      const track: Track = {
        id,
        ...parseTrackName(file.name),
        durationSec: Number.isFinite(durationSec) ? durationSec : 0,
        source: { kind: 'file', blobKey: id, fileName: file.name, mimeType: file.type || 'audio/mpeg', sizeBytes: file.size },
        addedAt: Date.now(),
      };
      this.registerTrack(track, alsoAddTo);
      result.added.push(track);
    }
    if (result.added.length) this.commit();
    return result;
  }

  addRemote(rawUrl: string, meta: { title?: string; artist?: string } = {}, alsoAddTo?: PlaylistId): Track {
    let url: URL;
    try {
      url = new URL(rawUrl.trim());
    } catch {
      throw new LibraryError('Enter a full link that starts with https://');
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new LibraryError('Only http and https links are supported.');
    const parsed = parseTrackName(decodeURIComponent(url.pathname.split('/').pop() ?? ''));
    const track: Track = {
      id: crypto.randomUUID(),
      title: meta.title?.trim() || parsed.title,
      artist: meta.artist?.trim() || parsed.artist,
      durationSec: 0,
      source: { kind: 'url', url: url.href, provider: detectProvider(url) },
      addedAt: Date.now(),
    };
    this.registerTrack(track, alsoAddTo);
    this.commit();
    return track;
  }

  setDuration(id: TrackId, durationSec: number): void {
    const track = this.tracks.get(id);
    if (!track || !Number.isFinite(durationSec) || Math.abs(track.durationSec - durationSec) < 0.5) return;
    track.durationSec = durationSec;
    this.commit();
  }

  createPlaylist(name: string): Playlist {
    const playlist = new Playlist(crypto.randomUUID(), this.validateName(name), false);
    this.playlists.push(playlist);
    this.commit();
    return playlist;
  }

  renamePlaylist(id: PlaylistId, name: string): void {
    const playlist = this.getPlaylist(id);
    if (playlist.system) throw new LibraryError(`"${MUSIC_PLAYLIST_NAME}" holds every upload and keeps its name.`);
    playlist.name = this.validateName(name, id);
    this.commit();
  }

  deletePlaylist(id: PlaylistId): void {
    const playlist = this.getPlaylist(id);
    if (playlist.system) throw new LibraryError(`"${MUSIC_PLAYLIST_NAME}" cannot be deleted.`);
    this.playlists.splice(this.playlists.indexOf(playlist), 1);
    playlist.tracks.clear();
    this.commit();
  }

  /** Returns false when the playlist already contains the track. */
  addToPlaylist(playlistId: PlaylistId, trackId: TrackId): boolean {
    const playlist = this.getPlaylist(playlistId);
    if (!this.tracks.has(trackId)) throw new LibraryError('That song no longer exists.');
    if (playlist.tracks.findNode((id) => id === trackId)) return false;
    playlist.tracks.append(trackId);
    this.commit();
    return true;
  }

  /** Removing from "Music" deletes the song from the whole library. */
  async removeFromPlaylist(playlistId: PlaylistId, index: number): Promise<void> {
    const playlist = this.getPlaylist(playlistId);
    if (playlist.system) {
      await this.deleteTrack(playlist.tracks.get(index));
      return;
    }
    playlist.tracks.removeAt(index);
    this.commit();
  }

  moveInPlaylist(playlistId: PlaylistId, from: number, to: number): void {
    this.getPlaylist(playlistId).tracks.move(from, to);
    this.commit();
  }

  async deleteTrack(id: TrackId): Promise<void> {
    const track = this.tracks.get(id);
    if (!track) return;
    for (const playlist of this.playlists) playlist.tracks.removeWhere((trackId) => trackId === id);
    this.tracks.delete(id);
    const objectUrl = this.objectUrls.get(id);
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    this.objectUrls.delete(id);
    if (track.source.kind === 'file') await this.blobs.delete(track.source.blobKey);
    this.commit();
  }

  /** All query tokens must match; title prefix matches rank first. */
  search(query: string): Track[] {
    const tokens = normalizeText(query).split(/\s+/).filter(Boolean);
    if (!tokens.length) return [];
    const scored: { track: Track; score: number }[] = [];
    for (const track of this.tracks.values()) {
      const title = normalizeText(track.title);
      const artist = normalizeText(track.artist);
      const extra = normalizeText(track.source.kind === 'file' ? track.source.fileName : track.source.provider);
      const haystack = `${title} ${artist} ${extra}`;
      if (!tokens.every((token) => haystack.includes(token))) continue;
      const first = tokens[0];
      const score = title.startsWith(first) ? 0 : title.includes(first) ? 1 : artist.includes(first) ? 2 : 3;
      scored.push({ track, score });
    }
    return scored.sort((a, b) => a.score - b.score || a.track.title.localeCompare(b.track.title)).map((entry) => entry.track);
  }

  async resolveSource(track: Track): Promise<string> {
    if (track.source.kind === 'url') return track.source.url;
    const cached = this.objectUrls.get(track.id);
    if (cached) return cached;
    const blob = await this.blobs.get(track.source.blobKey);
    if (!blob) throw new LibraryError(`The audio for "${track.title}" is missing from this device. Upload it again.`);
    const objectUrl = URL.createObjectURL(blob);
    this.objectUrls.set(track.id, objectUrl);
    return objectUrl;
  }

  private registerTrack(track: Track, alsoAddTo?: PlaylistId): void {
    this.tracks.set(track.id, track);
    this.music.tracks.append(track.id);
    if (alsoAddTo && alsoAddTo !== this.music.id) {
      const target = this.playlists.find((p) => p.id === alsoAddTo);
      target?.tracks.append(track.id);
    }
  }

  private validateName(raw: string, ignoreId?: PlaylistId): string {
    const name = raw.trim().replace(/\s+/g, ' ');
    if (!name) throw new LibraryError('Give the playlist a name.');
    if (name.length > MAX_PLAYLIST_NAME) throw new LibraryError(`Keep the name under ${MAX_PLAYLIST_NAME} characters.`);
    const clash = this.playlists.some((p) => p.id !== ignoreId && p.name.toLowerCase() === name.toLowerCase());
    if (clash) throw new LibraryError(`You already have a playlist called "${name}".`);
    return name;
  }

  toData(): LibraryData {
    return { version: 1, tracks: [...this.tracks.values()], playlists: this.playlists.map((p) => p.toData()) };
  }

  /** Replaces everything with a snapshot (used by the client to mirror the server). */
  replaceAll(data: LibraryData): void {
    this.tracks.clear();
    this.playlists.forEach((p) => p.tracks.clear());
    this.playlists.length = 0;
    this.apply(data);
    this.commit();
  }

  /** Adds a track created elsewhere (e.g. by the server) without generating a new id. */
  importTrack(track: Track, alsoAddTo?: PlaylistId): void {
    if (this.tracks.has(track.id)) return;
    this.registerTrack(track, alsoAddTo);
    this.commit();
  }

  private load(): void {
    let data: LibraryData | null = null;
    try {
      const raw = this.kv.get(this.storageKey);
      data = raw ? (JSON.parse(raw) as LibraryData) : null;
    } catch {
      data = null;
    }
    this.apply(data);
  }

  private apply(data: LibraryData | null): void {
    for (const track of data?.tracks ?? []) this.tracks.set(track.id, track);
    for (const p of data?.playlists ?? []) {
      const ids = p.trackIds.filter((id) => this.tracks.has(id));
      this.playlists.push(new Playlist(p.id, p.name, p.system, ids, p.createdAt));
    }
    const musicIndex = this.playlists.findIndex((p) => p.system);
    if (musicIndex === -1) this.playlists.unshift(new Playlist(crypto.randomUUID(), MUSIC_PLAYLIST_NAME, true));
    else if (musicIndex > 0) this.playlists.unshift(...this.playlists.splice(musicIndex, 1));
  }

  private commit(): void {
    this.kv.set(this.storageKey, JSON.stringify(this.toData()));
    this.listeners.forEach((listener) => listener());
  }
}
