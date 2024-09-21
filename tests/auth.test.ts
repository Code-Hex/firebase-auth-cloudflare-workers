import { describe, expect, it } from 'vitest';
import { ApiSettings } from '../src/api-requests';
import { BaseAuth } from '../src/auth';
import { AuthApiClient } from '../src/auth-api-requests';
import { AuthClientErrorCode, FirebaseAuthError } from '../src/errors';
import type { UserRecord } from '../src/user-record';
import { InMemoryStore } from './../src/index';
import type { EmulatorEnv } from './../src/index';
import {
  EmulatedSigner,
  FirebaseTokenGenerator,
  NopCredential,
  projectId,
  signInWithCustomToken,
} from './firebase-utils';

const env: EmulatorEnv = {
  FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099',
};

const sessionCookieUids = [
  generateRandomString(20),
  generateRandomString(20),
  generateRandomString(20),
  generateRandomString(20),
];

describe('createSessionCookie()', () => {
  const expiresIn = 24 * 60 * 60 * 1000;

  const uid = sessionCookieUids[0];
  const uid2 = sessionCookieUids[1];
  const uid3 = sessionCookieUids[2];
  const uid4 = sessionCookieUids[3];

  const signer = new EmulatedSigner();
  const tokenGenerator = new FirebaseTokenGenerator(signer);
  const keyStorer = new InMemoryStore();

  it('creates a valid Firebase session cookie', async () => {
    const auth = new BaseAuth(projectId, keyStorer, new NopCredential());

    const customToken = await tokenGenerator.createCustomToken(uid, { admin: true, groupId: '1234' });
    const { idToken } = await signInWithCustomToken(customToken, env);

    const decodedToken = await auth.verifyIdToken(idToken, false, env);

    const expectedExp = Math.floor((new Date().getTime() + expiresIn) / 1000);
    const want = {
      ...decodedToken,
      iss: decodedToken.iss.replace('securetoken.google.com', 'session.firebase.google.com'),
      exp: undefined,
      iat: undefined,
      auth_time: undefined,
    };
    const expectedIat = Math.floor(new Date().getTime() / 1000);

    const sessionCookie = await auth.createSessionCookie(idToken, { expiresIn }, env);
    const got = await auth.verifySessionCookie(sessionCookie, false, env);
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

  it('creates a revocable session cookie', async () => {
    const auth = new BaseAuth(projectId, keyStorer, new NopCredential());

    const customToken = await tokenGenerator.createCustomToken(uid2, { admin: true, groupId: '1234' });
    const { idToken } = await signInWithCustomToken(customToken, env);

    const sessionCookie = await auth.createSessionCookie(idToken, { expiresIn }, env);

    await new Promise(resolve => setTimeout(() => resolve(auth.revokeRefreshTokens(uid2, env)), 1000));

    await expect(auth.verifySessionCookie(sessionCookie, false, env)).resolves.toHaveProperty('uid', uid2);

    await expect(auth.verifySessionCookie(sessionCookie, true, env)).rejects.toThrowError(
      new FirebaseAuthError(AuthClientErrorCode.SESSION_COOKIE_REVOKED)
    );
  });

  it('fails when called with a revoked ID token', async () => {
    const auth = new BaseAuth(projectId, keyStorer, new NopCredential());

    const customToken = await tokenGenerator.createCustomToken(uid3, { admin: true, groupId: '1234' });
    const { idToken } = await signInWithCustomToken(customToken, env);

    await new Promise(resolve => setTimeout(() => resolve(auth.revokeRefreshTokens(uid3, env)), 1000));
    // auth/id-token-expired
    await expect(auth.createSessionCookie(idToken, { expiresIn }, env)).rejects.toThrowError(
      new FirebaseAuthError(AuthClientErrorCode.ID_TOKEN_EXPIRED)
    );
  });

  it('fails when called with user disabled', async () => {
    const expiresIn = 24 * 60 * 60 * 1000;
    const auth = new BaseAuth(projectId, keyStorer, new NopCredential());

    const customToken = await tokenGenerator.createCustomToken(uid4, { admin: true, groupId: '1234' });
    const { idToken } = await signInWithCustomToken(customToken, env);

    const decodedIdTokenClaims = await auth.verifyIdToken(idToken, false, env);
    expect(decodedIdTokenClaims.uid).toBe(uid4);

    const sessionCookie = await auth.createSessionCookie(idToken, { expiresIn }, env);
    const decodedIdToken = await auth.verifySessionCookie(sessionCookie, true, env);
    expect(decodedIdToken.uid).toBe(uid4);

    const cli = new TestAuthApiClient(projectId, new NopCredential());

    const userRecord = await cli.disableUser(uid4, env);
    // Ensure disabled field has been updated.
    expect(userRecord.uid).toBe(uid4);
    expect(userRecord.disabled).toBe(true);

    await expect(auth.createSessionCookie(idToken, { expiresIn }, env)).rejects.toThrowError(
      new FirebaseAuthError(AuthClientErrorCode.USER_DISABLED)
    );
  });
});

describe('verifySessionCookie()', () => {
  const uid = sessionCookieUids[0];
  const keyStorer = new InMemoryStore();
  const auth = new BaseAuth(projectId, keyStorer, new NopCredential());
  const signer = new EmulatedSigner();
  const tokenGenerator = new FirebaseTokenGenerator(signer);

  it('fails when called with an invalid session cookie', async () => {
    await expect(auth.verifySessionCookie('invalid-token', false, env)).rejects.toThrowError(FirebaseAuthError);
  });

  it('fails when called with a Firebase ID token', async () => {
    const customToken = await tokenGenerator.createCustomToken(uid, { admin: true, groupId: '1234' });
    const { idToken } = await signInWithCustomToken(customToken, env);

    await expect(auth.verifySessionCookie(idToken, false, env)).rejects.toThrowError(FirebaseAuthError);
  });

  it('fails with checkRevoked set to true and corresponding user disabled', async () => {
    const expiresIn = 24 * 60 * 60 * 1000;
    const customToken = await tokenGenerator.createCustomToken(uid, { admin: true, groupId: '1234' });
    const { idToken } = await signInWithCustomToken(customToken, env);

    const decodedIdTokenClaims = await auth.verifyIdToken(idToken, false, env);
    expect(decodedIdTokenClaims.uid).toBe(uid);

    const sessionCookie = await auth.createSessionCookie(idToken, { expiresIn }, env);
    const decodedIdToken = await auth.verifySessionCookie(sessionCookie, true, env);
    expect(decodedIdToken.uid).to.equal(uid);

    const cli = new TestAuthApiClient(projectId, new NopCredential());
    const userRecord = await cli.disableUser(uid, env);

    // Ensure disabled field has been updated.
    expect(userRecord.uid).to.equal(uid);
    expect(userRecord.disabled).to.equal(true);

    await expect(auth.verifySessionCookie(sessionCookie, false, env)).resolves.toHaveProperty('uid', uid);

    await expect(auth.verifySessionCookie(sessionCookie, true, env)).rejects.toThrowError(
      new FirebaseAuthError(AuthClientErrorCode.USER_DISABLED)
    );
  });
});

describe('getUser()', () => {
  const newUserUid = generateRandomString(20);
  const customClaims: { [key: string]: any } = {
    admin: true,
    groupId: '1234',
  };
  const keyStorer = new InMemoryStore();
  const auth = new BaseAuth(projectId, keyStorer, new NopCredential());
  const signer = new EmulatedSigner();
  const tokenGenerator = new FirebaseTokenGenerator(signer);

  it('setCustomUserClaims() sets claims that are accessible via user ID token', async () => {
    // Register user
    const customToken = await tokenGenerator.createCustomToken(newUserUid, {});
    await signInWithCustomToken(customToken, env);

    // Set custom claims on the user.
    await auth.setCustomUserClaims(newUserUid, customClaims, env);
    const userRecord = await auth.getUser(newUserUid, env);
    expect(userRecord.customClaims).toEqual(customClaims);

    const { idToken } = await signInWithCustomToken(customToken, env);
    const decodedIdToken = await auth.verifyIdToken(idToken, false, env);

    // Confirm expected claims set on the user's ID token.
    for (const key in customClaims) {
      if (Object.prototype.hasOwnProperty.call(customClaims, key)) {
        expect(decodedIdToken[key]).toEqual(customClaims[key]);
      }
    }

    // Test clearing of custom claims.
    await auth.setCustomUserClaims(newUserUid, null, env);
    const userRecord2 = await auth.getUser(newUserUid, env);

    // Custom claims should be cleared.
    expect(userRecord2.customClaims).toEqual({});

    // Confirm all custom claims are cleared from id token.
    const { idToken: idToken2 } = await signInWithCustomToken(customToken, env);
    const decodedIdToken2 = await auth.verifyIdToken(idToken2, false, env);

    for (const key in customClaims) {
      if (Object.prototype.hasOwnProperty.call(customClaims, key)) {
        expect(decodedIdToken2[key]).toBeUndefined();
      }
    }
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

const FIREBASE_AUTH_DISABLE_USER = new ApiSettings('v1', '/accounts:update', 'POST')
  // Set response validator.
  .setResponseValidator((response: any) => {
    // If the localId is not returned, then the request failed.
    if (!response.localId) {
      throw new FirebaseAuthError(AuthClientErrorCode.USER_NOT_FOUND);
    }
  });

class TestAuthApiClient extends AuthApiClient {
  public async disableUser(uid: string, env?: EmulatorEnv): Promise<UserRecord> {
    const request: any = {
      localId: uid,
      disableUser: true,
    };
    const { localId } = await this.fetch<{ localId: string }>(FIREBASE_AUTH_DISABLE_USER, request, env);
    return await this.getAccountInfoByUid(localId, env);
  }
}
