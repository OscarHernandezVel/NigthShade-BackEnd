import { createHmac, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import nodemailer from 'nodemailer';
import type { KeyValueStore, MailMessage, Mailer } from '../../shared/auth-service';
import type { BlobStore } from '../../shared/library-service';

/** JSON file database. Writes go to a temp file first, then rename, so a crash never leaves half a file. */
export class FileKeyValueStore implements KeyValueStore {
  private readonly data: Record<string, string>;

  constructor(private readonly file: string) {
    mkdirSync(dirname(file), { recursive: true });
    this.data = existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as Record<string, string>) : {};
  }

  get(key: string): string | null {
    return this.data[key] ?? null;
  }

  set(key: string, value: string): void {
    this.data[key] = value;
    this.flush();
  }

  remove(key: string): void {
    delete this.data[key];
    this.flush();
  }

  private flush(): void {
    const temp = `${this.file}.tmp`;
    writeFileSync(temp, JSON.stringify(this.data));
    renameSync(temp, this.file);
  }
}

const SAFE_KEY = /^[A-Za-z0-9-]+$/;

export class DiskBlobStore implements BlobStore {
  readonly root: string;

  constructor(root: string) {
    this.root = resolve(root);
    mkdirSync(this.root, { recursive: true });
  }

  pathFor(key: string): string {
    if (!SAFE_KEY.test(key)) throw new Error('Invalid blob key');
    return join(this.root, key);
  }

  async put(key: string, blob: Blob): Promise<void> {
    await mkdir(this.root, { recursive: true });
    await writeFile(this.pathFor(key), Buffer.from(await blob.arrayBuffer()));
  }

  async get(key: string): Promise<Blob | undefined> {
    const path = this.pathFor(key);
    return existsSync(path) ? new Blob([readFileSync(path)]) : undefined;
  }

  async delete(key: string): Promise<void> {
    await rm(this.pathFor(key), { force: true });
  }
}

export interface SmtpConfig {
  host: string;
  port: number;
  user?: string;
  pass?: string;
  from: string;
}

export function createMailer(smtp: SmtpConfig | null): Mailer {
  if (!smtp) {
    return {
      send: (message: MailMessage) => console.log(`[mail] to=${message.to} subject="${message.subject}" code=${message.code}`),
    };
  }
  const transport = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.port === 465,
    auth: smtp.user ? { user: smtp.user, pass: smtp.pass } : undefined,
  });
  const esc = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  return {
    send: async (message: MailMessage) => {
      const subject = esc(message.subject);
      const body = esc(message.body);
      await transport.sendMail({
        from: smtp.from,
        to: message.to,
        subject: message.subject,
        text: message.body,
        html: `<div style="font-family:sans-serif;background:#0b0710;color:#fff;padding:24px;border-radius:12px">
          <h2 style="color:#ff8c00;margin:0 0 12px">${subject}</h2><p>${body}</p>
          <p style="font-size:28px;letter-spacing:6px;font-weight:700;color:#ff8c00">${esc(message.code)}</p></div>`,
      });
    },
  };
}

const b64 = (value: Buffer | string) => Buffer.from(value).toString('base64url');

/** Compact HMAC-SHA256 token: base64url(json).base64url(signature). */
export function signToken(payload: Record<string, unknown>, secret: string, ttlSeconds: number): string {
  const body = b64(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
  return `${body}.${b64(createHmac('sha256', secret).update(body).digest())}`;
}

export function verifyToken<T extends Record<string, unknown>>(token: string, secret: string): T | null {
  const [body, signature] = token.split('.');
  if (!body || !signature) return null;
  const expected = createHmac('sha256', secret).update(body).digest();
  const given = Buffer.from(signature, 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as T & { exp: number };
    return payload.exp * 1000 > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

/** Fixed-window limiter, per key (IP + route). */
export function createRateLimiter(limit: number, windowMs: number) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return (key: string): boolean => {
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
