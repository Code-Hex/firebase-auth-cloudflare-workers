import { describe, expect, it } from 'vitest';
import { BaseAuth } from '../src/auth';
import { EmulatorCredential } from '../src/credential';
import { FirebaseAuthError } from '../src/errors';
import type { EmulatorEnv, KeyStorer } from './../src/index';
import { EmulatedSigner, FirebaseTokenGenerator, projectId, signInWithCustomToken } from './firebase-utils';

const env: EmulatorEnv = {
  FIREBASE_AUTH_EMULATOR_HOST: 'localhost:9099',
};

describe('createSessionCookie()', () => {
  const expiresIn = 24 * 60 * 60 * 1000;
  let currentIdToken: string;
  const sessionCookieUids = [
    generateRandomString(20),
    generateRandomString(20),
    generateRandomString(20),
    generateRandomString(20),
  ];
  const uid = sessionCookieUids[0];
  //   const uid2 = sessionCookieUids[1];
  //   const uid3 = sessionCookieUids[2];
  //   const uid4 = sessionCookieUids[3];

  it('creates a valid Firebase session cookie', async () => {
    const keyStorer = new InMemoryKeyStorer('cache-key');
    const auth = new BaseAuth(projectId, keyStorer, new EmulatorCredential());

    const signer = new EmulatedSigner();
    const tokenGenerator = new FirebaseTokenGenerator(signer);
    const customToken = await tokenGenerator.createCustomToken(uid, { admin: true, groupId: '1234' });
    const { idToken } = await signInWithCustomToken(customToken, env);
    currentIdToken = idToken;

    const decodedToken = await auth.verifyIdToken(idToken, env);

    const expectedExp = Math.floor((new Date().getTime() + expiresIn) / 1000);
    const want = {
      ...decodedToken,
      iss: decodedToken.iss.replace('securetoken.google.com', 'session.firebase.google.com'),
      exp: undefined,
      iat: undefined,
      auth_time: undefined,
    };
    const expectedIat = Math.floor(new Date().getTime() / 1000);

    const sessionCookie = await auth.createSessionCookie(currentIdToken, { expiresIn }, env);
    const got = await auth.verifySessionCookie(sessionCookie, env);
    // Check for expected expiration with +/-5 seconds of variation.
    expect(got.exp).to.be.within(expectedExp - 5, expectedExp + 5);
    expect(got.iat).to.be.within(expectedIat - 5, expectedIat + 5);

    expect({
      ...got,
      // exp and iat may vary depending on network connection latency.
      exp: undefined,
      iat: undefined,
      auth_time: undefined,
    }).to.deep.equal(want);
  });

  describe('verifySessionCookie()', () => {
    const uid = sessionCookieUids[0];
    const keyStorer = new InMemoryKeyStorer('cache-key');
    const auth = new BaseAuth(projectId, keyStorer, new EmulatorCredential());
    it('fails when called with an invalid session cookie', async () => {
      await expect(auth.verifySessionCookie('invalid-token')).rejects.toThrowError(FirebaseAuthError);
    });

    it('fails when called with a Firebase ID token', async () => {
      const signer = new EmulatedSigner();
      const tokenGenerator = new FirebaseTokenGenerator(signer);
      const customToken = await tokenGenerator.createCustomToken(uid, { admin: true, groupId: '1234' });
      const { idToken } = await signInWithCustomToken(customToken, env);

      await expect(auth.verifySessionCookie(idToken)).rejects.toThrowError(FirebaseAuthError);
    });
  });
});

function generateRandomString(stringLength: number) {
  const randomValues = new Uint8Array(stringLength);
  crypto.getRandomValues(randomValues);
  let randomString = '';
  for (let i = 0; i < stringLength; i++) {
    randomString += randomValues[i].toString(36)[0];
  }
  return randomString;
}

class InMemoryKeyStorer implements KeyStorer {
  private store: Map<string, unknown> = new Map();
  private timerId: NodeJS.Timeout | null = null;

  constructor(private readonly cacheKey: string) {}

  public async get<ExpectedValue = unknown>(): Promise<ExpectedValue | null> {
    return (this.store.get(this.cacheKey) as ExpectedValue) || null;
  }

  public async put(value: string, expirationTtl: number): Promise<void> {
    if (this.timerId) {
      clearTimeout(this.timerId);
    }
    this.store.set(this.cacheKey, value);
    this.timerId = setTimeout(() => this.store.delete(this.cacheKey), expirationTtl * 1000);
  }
}
