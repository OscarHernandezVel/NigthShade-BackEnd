import { join } from 'node:path';
import { createApp } from './app';
import { createMailer, DiskBlobStore, FileKeyValueStore } from './infra';

const env = process.env;
const port = Number(env.PORT ?? 4000);
const dataDir = env.DATA_DIR ?? join(process.cwd(), 'data');
const tokenSecret = env.TOKEN_SECRET ?? '';

if (tokenSecret.length < 32) {
  if (env.NODE_ENV === 'production') throw new Error('TOKEN_SECRET must be at least 32 characters in production.');
  console.warn('[config] TOKEN_SECRET is missing or short. Using an insecure development secret.');
}

const app = createApp(
  {
    tokenSecret: tokenSecret.length >= 32 ? tokenSecret : 'dev-only-secret-change-me-0123456789abcdef',
    corsOrigins: (env.CORS_ORIGIN ?? '*').split(',').map((origin) => origin.trim()),
    publicUrl: (env.PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, ''),
    maxUploadMb: Number(env.MAX_UPLOAD_MB ?? 50),
    exposeDevCodes: env.EXPOSE_DEV_CODES === 'true',
  },
  {
    kv: new FileKeyValueStore(join(dataDir, 'db.json')),
    blobs: new DiskBlobStore(join(dataDir, 'uploads')),
    mailer: createMailer(
      env.SMTP_HOST
        ? {
            host: env.SMTP_HOST,
            port: Number(env.SMTP_PORT ?? 587),
            user: env.SMTP_USER,
            pass: env.SMTP_PASS,
            from: env.MAIL_FROM ?? 'Nightshade <no-reply@nightshade.local>',
          }
        : null,
    ),
  },
);

app.listen(port, () => console.log(`Nightshade API listening on http://localhost:${port}`));
