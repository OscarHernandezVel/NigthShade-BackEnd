import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import multer from 'multer';
import { AuthError, AuthService, type AuthErrorCode, type KeyValueStore, type MailMessage, type Mailer } from '../../shared/auth-service';
import { LibraryError, LibraryService } from '../../shared/library-service';
import type { Session } from '../../shared/types';
import { createRateLimiter, signToken, verifyToken, type DiskBlobStore } from './infra';

export interface AppConfig {
  tokenSecret: string;
  corsOrigins: string[];
  publicUrl: string;
  maxUploadMb: number;
  /** Returns verification codes in API responses. Only for demos without SMTP. */
  exposeDevCodes: boolean;
  passwordIterations?: number;
}

export interface AppDeps {
  kv: KeyValueStore;
  blobs: DiskBlobStore;
  mailer: Mailer;
}

const SESSION_TTL = 60 * 60 * 24 * 7;
const STREAM_TTL = 60 * 60 * 6;

const STATUS: Record<AuthErrorCode, number> = {
  NAME_REQUIRED: 400,
  INVALID_EMAIL: 400,
  WEAK_PASSWORD: 400,
  INVALID_CODE: 400,
  CODE_EXPIRED: 400,
  EMAIL_TAKEN: 409,
  INVALID_CREDENTIALS: 401,
  EMAIL_NOT_VERIFIED: 403,
  TOO_MANY_ATTEMPTS: 429,
};

type AuthedRequest = Request & { session?: Session };

const str = (value: unknown) => (typeof value === 'string' ? value : '');
const int = (value: unknown) => {
  const n = Number(value);
  if (!Number.isInteger(n)) throw new LibraryError('Expected a whole number.');
  return n;
};

export function createApp(config: AppConfig, deps: AppDeps) {
  const lastMail = new Map<string, MailMessage>();
  const mailer: Mailer = {
    send: async (message) => {
      lastMail.set(message.to, message);
      await deps.mailer.send(message);
    },
  };
  const auth = new AuthService(deps.kv, mailer, { iterations: config.passwordIterations });
  const libraries = new Map<string, LibraryService>();
  const libraryFor = (userId: string) => {
    let library = libraries.get(userId);
    if (!library) {
      library = new LibraryService(userId, deps.kv, deps.blobs);
      libraries.set(userId, library);
    }
    return library;
  };
  const devCode = (email: string) => {
    if (!config.exposeDevCodes) return {};
    const mail = lastMail.get(email.trim().toLowerCase());
    return mail ? { devMail: { to: mail.to, subject: mail.subject, code: mail.code } } : {};
  };
  const issue = (session: Session) => ({ token: signToken({ sub: session.userId, typ: 'session' }, config.tokenSecret, SESSION_TTL), session });

  const app = express();
  app.disable('x-powered-by');
  app.use(cors({ origin: config.corsOrigins.includes('*') ? '*' : config.corsOrigins }));
  app.use(express.json({ limit: '100kb' }));
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  const limiter = createRateLimiter(30, 60_000);
  const limited = (req: Request, res: Response, next: NextFunction) => {
    if (limiter(`${req.ip}:${req.path}`)) return next();
    res.status(429).json({ error: 'TOO_MANY_REQUESTS', message: 'Too many requests. Wait a minute and try again.' });
  };

  const requireAuth = (req: AuthedRequest, res: Response, next: NextFunction) => {
    const header = req.headers.authorization ?? '';
    const payload = header.startsWith('Bearer ') ? verifyToken<{ sub: string; typ: string }>(header.slice(7), config.tokenSecret) : null;
    const user = payload?.typ === 'session' ? auth.findUser(payload.sub) : undefined;
    if (!user) return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Sign in again.' });
    req.session = { userId: user.id, email: user.email, displayName: user.displayName, issuedAt: Date.now() };
    next();
  };
  const library = (req: AuthedRequest) => libraryFor(req.session!.userId);

  app.get('/api/health', (_req, res) => res.json({ ok: true }));

  // ------------------------------------------------------------- auth
  app.post('/api/auth/register', limited, async (req, res) => {
    await auth.register(str(req.body.name), str(req.body.email), str(req.body.password));
    res.status(201).json({ ok: true, ...devCode(str(req.body.email)) });
  });
  app.post('/api/auth/resend', limited, async (req, res) => {
    await auth.resendVerification(str(req.body.email));
    res.json({ ok: true, ...devCode(str(req.body.email)) });
  });
  app.post('/api/auth/verify', limited, async (req, res) => {
    res.json(issue(await auth.verifyEmail(str(req.body.email), str(req.body.code))));
  });
  app.post('/api/auth/login', limited, async (req, res) => {
    res.json(issue(await auth.login(str(req.body.email), str(req.body.password))));
  });
  app.post('/api/auth/forgot', limited, async (req, res) => {
    await auth.requestPasswordReset(str(req.body.email));
    res.json({ ok: true, ...devCode(str(req.body.email)) });
  });
  app.post('/api/auth/reset', limited, async (req, res) => {
    await auth.resetPassword(str(req.body.email), str(req.body.code), str(req.body.password));
    res.json({ ok: true });
  });
  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => res.json({ session: req.session }));

  // ---------------------------------------------------------- library
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: config.maxUploadMb * 1024 * 1024, files: 50 } });

  app.get('/api/library', requireAuth, (req: AuthedRequest, res) => res.json(library(req).toData()));
  app.get('/api/search', requireAuth, (req: AuthedRequest, res) => res.json({ tracks: library(req).search(str(req.query.q)) }));

  app.post('/api/tracks/upload', requireAuth, upload.array('files'), async (req: AuthedRequest, res) => {
    const files = ((req.files as Express.Multer.File[] | undefined) ?? []).map(
      (f) => new File([new Uint8Array(f.buffer)], Buffer.from(f.originalname, 'latin1').toString('utf8'), { type: f.mimetype }),
    );
    const result = await library(req).addFiles(files, str(req.body.alsoAddTo) || undefined);
    res.status(201).json(result);
  });
  app.post('/api/tracks/remote', requireAuth, (req: AuthedRequest, res) => {
    const track = library(req).addRemote(str(req.body.url), { title: str(req.body.title), artist: str(req.body.artist) }, str(req.body.alsoAddTo) || undefined);
    res.status(201).json({ track });
  });
  app.patch('/api/tracks/:id', requireAuth, (req: AuthedRequest, res) => {
    library(req).setDuration(str(req.params.id), Number(req.body.durationSec));
    res.json({ ok: true });
  });
  app.delete('/api/tracks/:id', requireAuth, async (req: AuthedRequest, res) => {
    await library(req).deleteTrack(str(req.params.id));
    res.json({ ok: true });
  });
  app.get('/api/tracks/:id/stream-url', requireAuth, (req: AuthedRequest, res) => {
    const track = library(req).getTrack(str(req.params.id));
    if (!track) return res.status(404).json({ error: 'NOT_FOUND', message: 'That song no longer exists.' });
    if (track.source.kind === 'url') return res.json({ url: track.source.url });
    const sig = signToken({ sub: req.session!.userId, tid: track.id, typ: 'stream' }, config.tokenSecret, STREAM_TTL);
    res.json({ url: `${config.publicUrl}/api/stream/${track.id}?sig=${sig}` });
  });

  // Signed URL instead of the session token: <audio> cannot send headers.
  app.get('/api/stream/:id', (req, res) => {
    const payload = verifyToken<{ sub: string; tid: string; typ: string }>(str(req.query.sig), config.tokenSecret);
    if (!payload || payload.typ !== 'stream' || payload.tid !== req.params.id) return res.status(403).end();
    const track = libraryFor(payload.sub).getTrack(payload.tid);
    if (!track || track.source.kind !== 'file') return res.status(404).end();
    res.type(track.source.mimeType || 'audio/mpeg');
    res.sendFile(deps.blobs.pathFor(track.source.blobKey), { acceptRanges: true, cacheControl: false });
  });

  app.post('/api/playlists', requireAuth, (req: AuthedRequest, res) => res.status(201).json(library(req).createPlaylist(str(req.body.name)).toData()));
  app.patch('/api/playlists/:id', requireAuth, (req: AuthedRequest, res) => {
    library(req).renamePlaylist(str(req.params.id), str(req.body.name));
    res.json({ ok: true });
  });
  app.delete('/api/playlists/:id', requireAuth, (req: AuthedRequest, res) => {
    library(req).deletePlaylist(str(req.params.id));
    res.json({ ok: true });
  });
  app.post('/api/playlists/:id/tracks', requireAuth, (req: AuthedRequest, res) => {
    res.json({ added: library(req).addToPlaylist(str(req.params.id), str(req.body.trackId)) });
  });
  app.delete('/api/playlists/:id/tracks/:index', requireAuth, async (req: AuthedRequest, res) => {
    await library(req).removeFromPlaylist(str(req.params.id), int(req.params.index));
    res.json({ ok: true });
  });
  app.post('/api/playlists/:id/move', requireAuth, (req: AuthedRequest, res) => {
    library(req).moveInPlaylist(str(req.params.id), int(req.body.from), int(req.body.to));
    res.json({ ok: true });
  });

  app.use('/api', (_req, res) => res.status(404).json({ error: 'NOT_FOUND', message: 'Unknown endpoint.' }));

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof AuthError) return res.status(STATUS[error.code]).json({ error: error.code, message: error.message });
    if (error instanceof LibraryError || error instanceof RangeError) return res.status(400).json({ error: 'BAD_REQUEST', message: error.message });
    if (error instanceof multer.MulterError) {
      const message = error.code === 'LIMIT_FILE_SIZE' ? `Each file must be under ${config.maxUploadMb} MB.` : error.message;
      return res.status(413).json({ error: error.code, message });
    }
    console.error(error);
    res.status(500).json({ error: 'INTERNAL', message: 'Something went wrong on the server.' });
  });

  return app;
}
