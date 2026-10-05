import { mkdtempSync, rmSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DemoInbox } from '../../shared/auth-service';
import type { LibraryData } from '../../shared/types';
import { createApp } from '../src/app';
import { DiskBlobStore, FileKeyValueStore, signToken, verifyToken } from '../src/infra';

let server: Server;
let base = '';
let dir = '';
const inbox = new DemoInbox();
const SECRET = 'test-secret-that-is-long-enough-0123456789';

async function call<T = Record<string, unknown>>(method: string, path: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as T };
}

async function signUp(email: string): Promise<string> {
  await call('POST', '/api/auth/register', { name: 'Tester', email, password: 'pumpkin42' });
  const { body } = await call<{ token: string }>('POST', '/api/auth/verify', { email, code: inbox.messages[0].code });
  return body.token;
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'nightshade-'));
  const app = createApp(
    { tokenSecret: SECRET, corsOrigins: ['*'], publicUrl: '', maxUploadMb: 1, exposeDevCodes: true, passwordIterations: 1000 },
    { kv: new FileKeyValueStore(join(dir, 'db.json')), blobs: new DiskBlobStore(join(dir, 'uploads')), mailer: inbox },
  );
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => {
  server?.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('tokens', () => {
  it('rejects tampered and expired tokens', () => {
    const token = signToken({ sub: 'u' }, SECRET, 60);
    expect(verifyToken(token, SECRET)).toMatchObject({ sub: 'u' });
    expect(verifyToken(`${token}x`, SECRET)).toBeNull();
    expect(verifyToken(token, 'another-secret')).toBeNull();
    expect(verifyToken(signToken({ sub: 'u' }, SECRET, -1), SECRET)).toBeNull();
  });
});

describe('auth API', () => {
  it('runs register → verify → login → me', async () => {
    const reg = await call<{ devMail: { code: string } }>('POST', '/api/auth/register', { name: 'Ada', email: 'ada@test.dev', password: 'pumpkin42' });
    expect(reg.status).toBe(201);
    expect(reg.body.devMail.code).toMatch(/^\d{6}$/);

    expect((await call('POST', '/api/auth/login', { email: 'ada@test.dev', password: 'pumpkin42' })).status).toBe(403);
    expect((await call('POST', '/api/auth/verify', { email: 'ada@test.dev', code: 'nope' })).status).toBe(400);
    const verified = await call<{ token: string }>('POST', '/api/auth/verify', { email: 'ada@test.dev', code: reg.body.devMail.code });
    expect(verified.status).toBe(200);

    const login = await call<{ token: string }>('POST', '/api/auth/login', { email: 'ada@test.dev', password: 'pumpkin42' });
    const me = await call<{ session: { displayName: string } }>('GET', '/api/auth/me', undefined, login.body.token);
    expect(me.body.session.displayName).toBe('Ada');
  });

  it('returns proper errors', async () => {
    expect((await call('POST', '/api/auth/register', { name: 'A', email: 'bad', password: 'pumpkin42' })).status).toBe(400);
    expect((await call('POST', '/api/auth/register', { name: 'A', email: 'ada@test.dev', password: 'pumpkin42' })).status).toBe(409);
    expect((await call('POST', '/api/auth/login', { email: 'ada@test.dev', password: 'wrong1234' })).status).toBe(401);
    expect((await call('GET', '/api/library')).status).toBe(401);
    expect((await call('GET', '/api/library', undefined, 'forged.token')).status).toBe(401);
    expect((await call('GET', '/api/nothing')).status).toBe(404);
  });

  it('resets a password', async () => {
    const forgot = await call<{ devMail: { code: string } }>('POST', '/api/auth/forgot', { email: 'ada@test.dev' });
    expect((await call('POST', '/api/auth/reset', { email: 'ada@test.dev', code: forgot.body.devMail.code, password: 'newmoon99' })).status).toBe(200);
    expect((await call('POST', '/api/auth/login', { email: 'ada@test.dev', password: 'newmoon99' })).status).toBe(200);
    const ghost = await call('POST', '/api/auth/forgot', { email: 'ghost@test.dev' });
    expect(ghost).toEqual({ status: 200, body: { ok: true } });
  });
});

describe('library API', () => {
  let token = '';
  beforeAll(async () => {
    token = await signUp('lib@test.dev');
  });

  it('uploads songs into Music and streams them with Range support', async () => {
    const form = new FormData();
    form.append('files', new File([new Uint8Array(4096).fill(7)], 'Bauhaus - Bela Lugosi.mp3', { type: 'audio/mpeg' }));
    form.append('files', new File(['hello'], 'readme.txt', { type: 'text/plain' }));
    const upload = await call<{ added: { id: string; title: string }[]; rejected: unknown[] }>('POST', '/api/tracks/upload', form, token);
    expect(upload.status).toBe(201);
    expect(upload.body.added.map((t) => t.title)).toEqual(['Bela Lugosi']);
    expect(upload.body.rejected).toHaveLength(1);

    const library = (await call<LibraryData>('GET', '/api/library', undefined, token)).body;
    expect(library.playlists[0]).toMatchObject({ name: 'Music', system: true, trackIds: [upload.body.added[0].id] });

    const { body } = await call<{ url: string }>('GET', `/api/tracks/${upload.body.added[0].id}/stream-url`, undefined, token);
    const partial = await fetch(`${base}${body.url}`, { headers: { Range: 'bytes=0-99' } });
    expect(partial.status).toBe(206);
    expect((await partial.arrayBuffer()).byteLength).toBe(100);
    expect((await fetch(`${base}${body.url.replace(/sig=.+/, 'sig=forged')}`)).status).toBe(403);
  });

  it('rejects files over the size limit', async () => {
    const form = new FormData();
    form.append('files', new File([new Uint8Array(2 * 1024 * 1024)], 'big.mp3', { type: 'audio/mpeg' }));
    expect((await call('POST', '/api/tracks/upload', form, token)).status).toBe(413);
  });

  it('creates, fills, reorders, renames and deletes playlists', async () => {
    const ids: string[] = [];
    for (const name of ['One', 'Two', 'Three']) {
      const { body } = await call<{ track: { id: string } }>('POST', '/api/tracks/remote', { url: `https://archive.org/download/x/${name}.mp3` }, token);
      ids.push(body.track.id);
    }
    const created = await call<{ id: string }>('POST', '/api/playlists', { name: 'Night drive' }, token);
    expect(created.status).toBe(201);
    const pid = created.body.id;
    expect((await call('POST', '/api/playlists', { name: 'night drive' }, token)).status).toBe(400);
    for (const id of ids) await call('POST', `/api/playlists/${pid}/tracks`, { trackId: id }, token);
    expect((await call('POST', `/api/playlists/${pid}/tracks`, { trackId: ids[0] }, token)).body).toEqual({ added: false });
    await call('POST', `/api/playlists/${pid}/move`, { from: 0, to: 2 }, token);
    expect((await call('POST', `/api/playlists/${pid}/move`, { from: 0, to: 9 }, token)).status).toBe(400);
    await call('PATCH', `/api/playlists/${pid}`, { name: 'Moonlight' }, token);
    await call('DELETE', `/api/playlists/${pid}/tracks/0`, undefined, token);

    const library = (await call<LibraryData>('GET', '/api/library', undefined, token)).body;
    const playlist = library.playlists.find((p) => p.id === pid)!;
    expect(playlist.name).toBe('Moonlight');
    expect(playlist.trackIds).toEqual([ids[2], ids[0]]);

    const search = await call<{ tracks: { title: string }[] }>('GET', '/api/search?q=thr', undefined, token);
    expect(search.body.tracks.map((t) => t.title)).toEqual(['Three']);

    expect((await call('DELETE', `/api/playlists/${library.playlists[0].id}`, undefined, token)).status).toBe(400);
    expect((await call('DELETE', `/api/playlists/${pid}`, undefined, token)).status).toBe(200);
  });

  it('keeps each user library private', async () => {
    const other = await signUp('other@test.dev');
    const library = (await call<LibraryData>('GET', '/api/library', undefined, other)).body;
    expect(library.tracks).toEqual([]);
  });
});
