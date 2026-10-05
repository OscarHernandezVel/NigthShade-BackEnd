import { describe, expect, it } from 'vitest';
import { AuthError, AuthService, CODE_TTL_MS, DemoInbox, MAX_CODE_ATTEMPTS, MemoryStore } from '../../shared/auth-service';
import { DoublyLinkedList, FifoQueue } from '../../shared/linked-list';
import { LibraryService, MemoryBlobStore, detectProvider, isSupportedAudio, parseTrackName } from '../../shared/library-service';

const mp3 = (name: string, bytes = 16) => new File([new Uint8Array(bytes)], name, { type: 'audio/mpeg' });

describe('DoublyLinkedList', () => {
  it('appends, prepends, inserts and walks both directions', () => {
    const list = new DoublyLinkedList([2, 3]);
    list.prepend(1);
    list.insertAt(3, 4);
    list.insertAt(2, 2.5);
    expect(list.toArray()).toEqual([1, 2, 2.5, 3, 4]);
    expect([...list.reversed()]).toEqual([4, 3, 2.5, 2, 1]);
    expect(list.first?.prev).toBeNull();
    expect(list.last?.next).toBeNull();
    list.checkIntegrity();
  });

  it('moves nodes without recreating them, so external pointers stay valid', () => {
    const list = new DoublyLinkedList(['a', 'b', 'c', 'd']);
    const node = list.nodeAt(0);
    list.move(0, 3);
    expect(list.toArray()).toEqual(['b', 'c', 'd', 'a']);
    expect(list.nodeAt(3)).toBe(node);
    expect(list.contains(node)).toBe(true);
    list.checkIntegrity();
  });

  it('matches array splice semantics on 2,000 random operations', () => {
    const list = new DoublyLinkedList<number>();
    const model: number[] = [];
    let seed = 42;
    const rand = (n: number) => (seed = (seed * 1103515245 + 12345) % 2 ** 31) % n;
    for (let i = 0; i < 2000; i++) {
      const op = model.length ? rand(4) : 0;
      if (op === 0) {
        const at = rand(model.length + 1);
        list.insertAt(at, i);
        model.splice(at, 0, i);
      } else if (op === 1) {
        const at = rand(model.length);
        expect(list.removeAt(at)).toBe(model.splice(at, 1)[0]);
      } else if (op === 2) {
        const from = rand(model.length);
        const to = rand(model.length);
        list.move(from, to);
        model.splice(to, 0, model.splice(from, 1)[0]);
      } else {
        const at = rand(model.length);
        expect(list.get(at)).toBe(model[at]);
      }
      expect(list.size).toBe(model.length);
    }
    expect(list.toArray()).toEqual(model);
    list.checkIntegrity();
  });

  it('rejects bad indices and foreign nodes', () => {
    const list = new DoublyLinkedList([1]);
    expect(() => list.get(1)).toThrow(RangeError);
    expect(() => list.insertAt(-1, 0)).toThrow(RangeError);
    expect(() => list.move(0, 1.5)).toThrow(RangeError);
    const other = new DoublyLinkedList([9]);
    expect(() => list.removeNode(other.nodeAt(0))).toThrow();
  });

  it('removes matches in one pass and clears', () => {
    const list = new DoublyLinkedList([1, 2, 1, 3, 1]);
    expect(list.removeWhere((v) => v === 1)).toBe(3);
    expect(list.toArray()).toEqual([2, 3]);
    list.clear();
    expect(list.size).toBe(0);
    list.checkIntegrity();
  });
});

describe('FifoQueue', () => {
  it('dequeues in insertion order and supports reordering', () => {
    const queue = new FifoQueue<string>();
    expect(queue.dequeue()).toBeUndefined();
    ['a', 'b', 'c'].forEach((v) => queue.enqueue(v));
    queue.move(2, 0);
    expect(queue.peek()).toBe('c');
    expect([queue.dequeue(), queue.dequeue(), queue.dequeue()]).toEqual(['c', 'a', 'b']);
    expect(queue.isEmpty()).toBe(true);
    queue.checkIntegrity();
  });
});

describe('AuthService', () => {
  const setup = () => {
    let now = 1_000_000;
    const inbox = new DemoInbox();
    const auth = new AuthService(new MemoryStore(), inbox, { iterations: 1000, now: () => now });
    return { auth, inbox, tick: (ms: number) => (now += ms) };
  };
  const code = (inbox: DemoInbox) => inbox.messages[0].code;

  it('registers, requires verification, then signs in', async () => {
    const { auth, inbox } = setup();
    await auth.register('Ada', 'Ada@Example.com', 'pumpkin42');
    expect(inbox.messages[0]).toMatchObject({ to: 'ada@example.com', purpose: 'verify' });
    await expect(auth.login('ada@example.com', 'pumpkin42')).rejects.toMatchObject({ code: 'EMAIL_NOT_VERIFIED' });
    const session = await auth.verifyEmail('ada@example.com', code(inbox));
    expect(session.displayName).toBe('Ada');
    expect((await auth.login(' ADA@example.com ', 'pumpkin42')).userId).toBe(session.userId);
  });

  it('validates input and refuses duplicates', async () => {
    const { auth } = setup();
    await expect(auth.register('', 'a@b.co', 'pumpkin42')).rejects.toMatchObject({ code: 'NAME_REQUIRED' });
    await expect(auth.register('A', 'not-an-email', 'pumpkin42')).rejects.toMatchObject({ code: 'INVALID_EMAIL' });
    await expect(auth.register('A', 'a@b.co', 'short1')).rejects.toMatchObject({ code: 'WEAK_PASSWORD' });
    await expect(auth.register('A', 'a@b.co', 'lettersonly')).rejects.toMatchObject({ code: 'WEAK_PASSWORD' });
    await auth.register('A', 'a@b.co', 'pumpkin42');
    await expect(auth.register('B', 'A@B.CO', 'pumpkin42')).rejects.toMatchObject({ code: 'EMAIL_TAKEN' });
  });

  it('uses the same error for a wrong password and an unknown email', async () => {
    const { auth, inbox } = setup();
    await auth.register('A', 'a@b.co', 'pumpkin42');
    await auth.verifyEmail('a@b.co', code(inbox));
    const wrong = await auth.login('a@b.co', 'nope12345').catch((e: AuthError) => e);
    const unknown = await auth.login('x@b.co', 'nope12345').catch((e: AuthError) => e);
    expect(wrong).toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(unknown).toMatchObject({ code: 'INVALID_CREDENTIALS', message: (wrong as AuthError).message });
  });

  it('limits code attempts and expires codes', async () => {
    const { auth, inbox, tick } = setup();
    await auth.register('A', 'a@b.co', 'pumpkin42');
    for (let i = 0; i < MAX_CODE_ATTEMPTS; i++) await expect(auth.verifyEmail('a@b.co', '000000x')).rejects.toMatchObject({ code: 'INVALID_CODE' });
    await expect(auth.verifyEmail('a@b.co', code(inbox))).rejects.toMatchObject({ code: 'TOO_MANY_ATTEMPTS' });
    await auth.resendVerification('a@b.co');
    tick(CODE_TTL_MS + 1);
    await expect(auth.verifyEmail('a@b.co', code(inbox))).rejects.toMatchObject({ code: 'CODE_EXPIRED' });
  });

  it('resets a password with an emailed code and never reveals unknown emails', async () => {
    const { auth, inbox } = setup();
    await auth.register('A', 'a@b.co', 'pumpkin42');
    await auth.requestPasswordReset('ghost@b.co');
    expect(inbox.messages).toHaveLength(1);
    await auth.requestPasswordReset('a@b.co');
    expect(inbox.messages[0].purpose).toBe('reset');
    await expect(auth.verifyEmail('a@b.co', code(inbox))).rejects.toMatchObject({ code: 'INVALID_CODE' });
    await auth.resetPassword('a@b.co', code(inbox), 'newmoon99');
    await expect(auth.login('a@b.co', 'pumpkin42')).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect((await auth.login('a@b.co', 'newmoon99')).email).toBe('a@b.co');
  });
});

describe('LibraryService', () => {
  const setup = () => {
    const kv = new MemoryStore();
    const blobs = new MemoryBlobStore();
    return { kv, blobs, library: new LibraryService('u1', kv, blobs, async () => 180) };
  };

  it('starts with one empty system playlist called Music', () => {
    const { library } = setup();
    expect(library.playlists.map((p) => [p.name, p.system, p.tracks.size])).toEqual([['Music', true, 0]]);
  });

  it('adds audio uploads to Music and rejects other files', async () => {
    const { library, blobs } = setup();
    const result = await library.addFiles([mp3('Nina Simone - Feeling Good.mp3'), new File(['x'], 'notes.txt', { type: 'text/plain' })]);
    expect(result.added).toHaveLength(1);
    expect(result.rejected[0]).toMatchObject({ name: 'notes.txt' });
    const [track] = result.added;
    expect(track).toMatchObject({ title: 'Feeling Good', artist: 'Nina Simone', durationSec: 180 });
    expect(library.music.tracks.toArray()).toEqual([track.id]);
    expect(await blobs.get(track.id)).toBeDefined();
  });

  it('creates, renames, orders and deletes playlists', async () => {
    const { library } = setup();
    const { added } = await library.addFiles([mp3('a.mp3'), mp3('b.mp3'), mp3('c.mp3')]);
    const night = library.createPlaylist('  Night   drive ');
    expect(night.name).toBe('Night drive');
    expect(() => library.createPlaylist('night DRIVE')).toThrow(/already/);
    expect(() => library.renamePlaylist(library.music.id, 'X')).toThrow();
    added.forEach((t) => library.addToPlaylist(night.id, t.id));
    expect(library.addToPlaylist(night.id, added[0].id)).toBe(false);
    library.moveInPlaylist(night.id, 0, 2);
    expect(library.playlistTracks(night.id).map((t) => t.title)).toEqual(['b', 'c', 'a']);
    library.renamePlaylist(night.id, 'Moonlight');
    await library.removeFromPlaylist(night.id, 0);
    expect(library.music.tracks.size).toBe(3);
    library.deletePlaylist(night.id);
    expect(() => library.deletePlaylist(library.music.id)).toThrow();
    expect(library.playlists).toHaveLength(1);
  });

  it('deleting from Music removes the song everywhere', async () => {
    const { library, blobs } = setup();
    const { added } = await library.addFiles([mp3('a.mp3'), mp3('b.mp3')]);
    const mix = library.createPlaylist('Mix');
    library.addToPlaylist(mix.id, added[0].id);
    await library.removeFromPlaylist(library.music.id, 0);
    expect(library.tracks.has(added[0].id)).toBe(false);
    expect(mix.tracks.size).toBe(0);
    expect(await blobs.get(added[0].id)).toBeUndefined();
  });

  it('searches titles, artists and file names, ignoring accents', async () => {
    const { library } = setup();
    await library.addFiles([mp3('Café Tacvba - Eres.mp3'), mp3('Bauhaus - Bela Lugosi.mp3'), mp3('Eres tu.mp3')]);
    expect(library.search('cafe').map((t) => t.title)).toEqual(['Eres']);
    expect(library.search('eres').map((t) => t.title)).toEqual(['Eres', 'Eres tu']);
    expect(library.search('bauhaus lugosi')).toHaveLength(1);
    expect(library.search('   ')).toEqual([]);
  });

  it('accepts links from open music repositories', () => {
    const { library } = setup();
    const track = library.addRemote('https://archive.org/download/set/Artist%20-%20Song.mp3');
    expect(track).toMatchObject({ title: 'Song', artist: 'Artist', source: { kind: 'url', provider: 'internet-archive' } });
    expect(() => library.addRemote('ftp://x.org/a.mp3')).toThrow();
    expect(() => library.addRemote('not a url')).toThrow();
  });

  it('persists and mirrors snapshots', async () => {
    const { library, kv, blobs } = setup();
    await library.addFiles([mp3('a.mp3')]);
    const mix = library.createPlaylist('Mix');
    const reloaded = new LibraryService('u1', kv, blobs);
    expect(reloaded.toData()).toEqual(library.toData());
    const mirror = new LibraryService('u2', new MemoryStore(), new MemoryBlobStore());
    mirror.replaceAll(library.toData());
    expect(mirror.getPlaylist(mix.id).name).toBe('Mix');
    mirror.importTrack({ ...library.music.tracks.toArray().map((id) => library.getTrack(id)!)[0], id: 'remote-1' });
    expect(mirror.music.tracks.size).toBe(2);
  });
});

describe('helpers', () => {
  it('parses file names and detects providers and formats', () => {
    expect(parseTrackName('My_Song.mp3')).toEqual({ artist: 'Unknown artist', title: 'My Song' });
    expect(parseTrackName('A - B - C.flac')).toEqual({ artist: 'A', title: 'B - C' });
    expect(detectProvider(new URL('https://cdn.jamendo.com/x.mp3'))).toBe('jamendo');
    expect(detectProvider(new URL('https://example.com/x.mp3'))).toBe('other');
    expect(isSupportedAudio({ name: 'x.MP3', type: '' })).toBe(true);
    expect(isSupportedAudio({ name: 'x.exe', type: 'application/x-msdownload' })).toBe(false);
  });
});
