import type { CodePurpose, Session, UserRecord } from './types';

export interface KeyValueStore {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export class MemoryStore implements KeyValueStore {
  private readonly map = new Map<string, string>();
  get(key: string) {
    return this.map.get(key) ?? null;
  }
  set(key: string, value: string) {
    this.map.set(key, value);
  }
  remove(key: string) {
    this.map.delete(key);
  }
}

export interface MailMessage {
  to: string;
  subject: string;
  body: string;
  code: string;
  purpose: CodePurpose;
  sentAt: number;
}

export interface Mailer {
  send(message: MailMessage): void | Promise<void>;
}

/** Keeps mail in memory: used by the browser demo and by tests. The backend uses SMTP. */
export class DemoInbox implements Mailer {
  readonly messages: MailMessage[] = [];
  private readonly listeners = new Set<(message: MailMessage) => void>();

  send(message: MailMessage): void {
    this.messages.unshift(message);
    this.listeners.forEach((listener) => listener(message));
  }

  subscribe(listener: (message: MailMessage) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

export type AuthErrorCode =
  | 'NAME_REQUIRED'
  | 'INVALID_EMAIL'
  | 'WEAK_PASSWORD'
  | 'EMAIL_TAKEN'
  | 'INVALID_CREDENTIALS'
  | 'EMAIL_NOT_VERIFIED'
  | 'INVALID_CODE'
  | 'CODE_EXPIRED'
  | 'TOO_MANY_ATTEMPTS';

export class AuthError extends Error {
  constructor(
    readonly code: AuthErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
export const CODE_TTL_MS = 10 * 60 * 1000;
export const MAX_CODE_ATTEMPTS = 5;
const USERS_KEY = 'ns.users';

export function validatePassword(password: string): string | null {
  if (password.length < 8) return 'Use at least 8 characters.';
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) return 'Mix letters and numbers.';
  return null;
}

const encoder = new TextEncoder();
const toHex = (buffer: ArrayBuffer | Uint8Array) =>
  Array.from(buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex: string) => new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));

export interface AuthOptions {
  iterations?: number;
  now?: () => number;
}

export class AuthService {
  private readonly iterations: number;
  private readonly now: () => number;

  constructor(
    private readonly store: KeyValueStore,
    private readonly mailer: Mailer,
    options: AuthOptions = {},
  ) {
    this.iterations = options.iterations ?? 120_000;
    this.now = options.now ?? Date.now;
  }

  async register(displayName: string, email: string, password: string): Promise<void> {
    const name = displayName.trim();
    const address = this.normalize(email);
    if (!name) throw new AuthError('NAME_REQUIRED', 'Enter your name.');
    if (!EMAIL_PATTERN.test(address)) throw new AuthError('INVALID_EMAIL', 'Enter a valid email address.');
    const weakness = validatePassword(password);
    if (weakness) throw new AuthError('WEAK_PASSWORD', weakness);

    const users = this.loadUsers();
    if (users[address]) throw new AuthError('EMAIL_TAKEN', 'An account with this email already exists. Sign in instead.');

    const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const user: UserRecord = {
      id: crypto.randomUUID(),
      email: address,
      displayName: name,
      salt,
      passwordHash: await this.hashPassword(password, salt),
      verified: false,
      createdAt: this.now(),
      pendingCode: null,
    };
    users[address] = user;
    await this.issueCode(users, user, 'verify');
  }

  async resendVerification(email: string): Promise<void> {
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (user && !user.verified) await this.issueCode(users, user, 'verify');
  }

  async verifyEmail(email: string, code: string): Promise<Session> {
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (!user) throw new AuthError('INVALID_CODE', 'That code is not valid.');
    await this.consumeCode(users, user, 'verify', code);
    user.verified = true;
    this.saveUsers(users);
    return this.startSession(user);
  }

  async login(email: string, password: string): Promise<Session> {
    const user = this.loadUsers()[this.normalize(email)];
    const valid = user ? (await this.hashPassword(password, user.salt)) === user.passwordHash : false;
    if (!user || !valid) throw new AuthError('INVALID_CREDENTIALS', 'Email or password is incorrect.');
    if (!user.verified) throw new AuthError('EMAIL_NOT_VERIFIED', 'Verify your email before signing in.');
    return this.startSession(user);
  }

  /** Always resolves, so the response never reveals whether an account exists. */
  async requestPasswordReset(email: string): Promise<void> {
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (user) await this.issueCode(users, user, 'reset');
  }

  async resetPassword(email: string, code: string, newPassword: string): Promise<void> {
    const weakness = validatePassword(newPassword);
    if (weakness) throw new AuthError('WEAK_PASSWORD', weakness);
    const users = this.loadUsers();
    const user = users[this.normalize(email)];
    if (!user) throw new AuthError('INVALID_CODE', 'That code is not valid.');
    await this.consumeCode(users, user, 'reset', code);
    user.salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    user.passwordHash = await this.hashPassword(newPassword, user.salt);
    user.verified = true;
    this.saveUsers(users);
  }

  findUser(userId: string): UserRecord | undefined {
    return Object.values(this.loadUsers()).find((user) => user.id === userId);
  }

  private startSession(user: UserRecord): Session {
    return { userId: user.id, email: user.email, displayName: user.displayName, issuedAt: this.now() };
  }

  private async issueCode(users: Record<string, UserRecord>, user: UserRecord, purpose: CodePurpose): Promise<void> {
    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, '0');
    user.pendingCode = { hash: await this.sha256(`${purpose}:${code}`), purpose, expiresAt: this.now() + CODE_TTL_MS, attempts: 0 };
    this.saveUsers(users);
    const subject = purpose === 'verify' ? 'Verify your Nightshade account' : 'Reset your Nightshade password';
    const body =
      purpose === 'verify'
        ? `Hi ${user.displayName}, your verification code is ${code}. It expires in 10 minutes.`
        : `Your password reset code is ${code}. It expires in 10 minutes. Ignore this email if you did not ask for it.`;
    await this.mailer.send({ to: user.email, subject, body, code, purpose, sentAt: this.now() });
  }

  private async consumeCode(users: Record<string, UserRecord>, user: UserRecord, purpose: CodePurpose, code: string): Promise<void> {
    const pending = user.pendingCode;
    if (!pending || pending.purpose !== purpose) throw new AuthError('INVALID_CODE', 'That code is not valid. Request a new one.');
    if (this.now() > pending.expiresAt) {
      user.pendingCode = null;
      this.saveUsers(users);
      throw new AuthError('CODE_EXPIRED', 'That code has expired. Request a new one.');
    }
    if (pending.attempts >= MAX_CODE_ATTEMPTS) throw new AuthError('TOO_MANY_ATTEMPTS', 'Too many attempts. Request a new code.');
    if ((await this.sha256(`${purpose}:${code.trim()}`)) !== pending.hash) {
      pending.attempts++;
      this.saveUsers(users);
      const left = MAX_CODE_ATTEMPTS - pending.attempts;
      throw new AuthError('INVALID_CODE', `That code is not valid. ${left} attempt${left === 1 ? '' : 's'} left.`);
    }
    user.pendingCode = null;
  }

  private async hashPassword(password: string, saltHex: string): Promise<string> {
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: this.iterations },
      key,
      256,
    );
    return toHex(bits);
  }

  private async sha256(text: string): Promise<string> {
    return toHex(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
  }

  private normalize(email: string): string {
    return email.trim().toLowerCase();
  }

  private loadUsers(): Record<string, UserRecord> {
    try {
      return JSON.parse(this.store.get(USERS_KEY) ?? '{}') as Record<string, UserRecord>;
    } catch {
      return {};
    }
  }

  private saveUsers(users: Record<string, UserRecord>): void {
    this.store.set(USERS_KEY, JSON.stringify(users));
  }
}
