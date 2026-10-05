export type TrackId = string;
export type PlaylistId = string;

export const SUPPORTED_AUDIO_EXTENSIONS = ['.mp3', '.ogg', '.wav', '.flac', '.m4a', '.aac', '.webm'] as const;
export type AudioExtension = (typeof SUPPORTED_AUDIO_EXTENSIONS)[number];

export const SUPPORTED_AUDIO_MIME_TYPES = [
  'audio/mpeg',
  'audio/mp3',
  'audio/ogg',
  'audio/wav',
  'audio/x-wav',
  'audio/flac',
  'audio/mp4',
  'audio/x-m4a',
  'audio/aac',
  'audio/webm',
] as const;
export type AudioMimeType = (typeof SUPPORTED_AUDIO_MIME_TYPES)[number];

export const OPEN_MUSIC_PROVIDERS = [
  { id: 'internet-archive', label: 'Internet Archive', host: 'archive.org' },
  { id: 'jamendo', label: 'Jamendo', host: 'jamendo.com' },
  { id: 'free-music-archive', label: 'Free Music Archive', host: 'freemusicarchive.org' },
  { id: 'ccmixter', label: 'ccMixter', host: 'ccmixter.org' },
  { id: 'github', label: 'GitHub', host: 'githubusercontent.com' },
  { id: 'wikimedia', label: 'Wikimedia Commons', host: 'wikimedia.org' },
] as const;
export type OpenMusicProvider = (typeof OPEN_MUSIC_PROVIDERS)[number]['id'] | 'other';

/** An audio file uploaded from the user's device and kept in IndexedDB. */
export interface LocalFileSource {
  kind: 'file';
  blobKey: string;
  fileName: string;
  mimeType: AudioMimeType | string;
  sizeBytes: number;
}

/** A direct link to an audio file hosted by an open music repository. */
export interface RemoteUrlSource {
  kind: 'url';
  url: string;
  provider: OpenMusicProvider;
}

export type TrackSource = LocalFileSource | RemoteUrlSource;

export interface Track {
  id: TrackId;
  title: string;
  artist: string;
  durationSec: number;
  source: TrackSource;
  addedAt: number;
}

export interface PlaylistData {
  id: PlaylistId;
  name: string;
  system: boolean;
  trackIds: TrackId[];
  createdAt: number;
}

export interface LibraryData {
  version: 1;
  tracks: Track[];
  playlists: PlaylistData[];
}

export type CodePurpose = 'verify' | 'reset';

export interface PendingCode {
  hash: string;
  purpose: CodePurpose;
  expiresAt: number;
  attempts: number;
}

export interface UserRecord {
  id: string;
  email: string;
  displayName: string;
  passwordHash: string;
  salt: string;
  verified: boolean;
  createdAt: number;
  pendingCode: PendingCode | null;
}

export interface Session {
  userId: string;
  email: string;
  displayName: string;
  issuedAt: number;
}

export const MUSIC_PLAYLIST_NAME = 'Music';
