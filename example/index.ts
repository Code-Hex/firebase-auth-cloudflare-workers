import { Hono } from 'hono';
import { Auth, emulatorHost, WorkersKVStoreSingle } from '../src';

type Env = {
  EMAIL_ADDRESS: string;
  PASSWORD: string;
  PUBLIC_JWK_CACHE_KV: KVNamespace;
  PROJECT_ID: string;
  PUBLIC_JWK_CACHE_KEY: string;

  FIREBASE_AUTH_EMULATOR_HOST: string; // satisfied EmulatorEnv
};

const app = new Hono<{ Bindings: Env }>();

const signInPath = '/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=test1234';

app.get('/get-jwt', async c => {
  const firebaseEmuHost = emulatorHost(c.env);
  const firebaseEmulatorSignInUrl = 'http://' + firebaseEmuHost + signInPath;
  return await fetch(firebaseEmulatorSignInUrl, {
    method: 'POST',
    body: JSON.stringify({
      email: c.env.EMAIL_ADDRESS,
      password: c.env.PASSWORD,
      returnSecureToken: true,
    }),
    headers: {
      'Content-Type': 'application/json',
    },
  });
});

app.post('/verify-header', async c => {
  const authorization = c.req.raw.headers.get('Authorization');
  if (authorization === null) {
    return new Response(null, {
      status: 400,
    });
  }
  const jwt = authorization.replace(/Bearer\s+/i, '');
  const auth = Auth.getOrInitialize(
    c.env.PROJECT_ID,
    WorkersKVStoreSingle.getOrInitialize(c.env.PUBLIC_JWK_CACHE_KEY, c.env.PUBLIC_JWK_CACHE_KV)
  );
  const firebaseToken = await auth.verifyIdToken(jwt, c.env);

  return new Response(JSON.stringify(firebaseToken), {
    headers: {
      'Content-Type': 'application/json',
    },
  });
});

export default app;
