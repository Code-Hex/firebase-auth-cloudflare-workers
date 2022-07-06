import { PublicKeySignatureVerifier, rs256alg } from '../src/jws-verifier';
import type { FirebaseIdToken } from '../src/token-verifier';
import { createFirebaseTokenVerifier, FIREBASE_AUDIENCE } from '../src/token-verifier';
import { genIss, genTime, signJWT, TestingKeyFetcher } from './jwk-utils';

describe('FirebaseTokenVerifier', () => {
  const kid = 'kid123456';
  const projectId = 'projectId1234';
  const currentTimestamp = genTime(Date.now());
  const userId = 'userId12345';
  const payload: FirebaseIdToken = {
    aud: projectId,
    exp: currentTimestamp + 9999,
    iat: currentTimestamp - 10000, // -10s
    iss: genIss(projectId),
    sub: userId,
    auth_time: currentTimestamp - 20000, // -20s
    uid: userId,
    firebase: {
      identities: {},
      sign_in_provider: 'google.com',
    },
  };

  test.each([
    ['valid without firebase emulator', payload],
    [
      'valid custom token without firebase emulator',
      {
        ...payload,
        aud: FIREBASE_AUDIENCE,
      },
    ],
  ])('%s', async (_, payload) => {
    const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration(kid);
    const jwt = await signJWT(kid, payload, testingKeyFetcher.getPrivateKey());

    const verifier = new PublicKeySignatureVerifier(testingKeyFetcher);
    const ftv = createFirebaseTokenVerifier(verifier, projectId);
    const token = await ftv.verifyJWT(jwt, false);

    expect(token).toStrictEqual(payload);
  });

  it('valid with firebase emulator', async () => {
    const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration(kid);

    // sign as invalid private key with fetched public key
    const keyPair = await crypto.subtle.generateKey(rs256alg, true, ['sign', 'verify']);

    // set with invalid kid because jwt does not contain kid which issued from firebase emulator.
    const jwt = await signJWT('invalid-kid', payload, keyPair.privateKey);

    const verifier = new PublicKeySignatureVerifier(testingKeyFetcher);
    const ftv = createFirebaseTokenVerifier(verifier, projectId);

    // firebase emulator ignores signature verification step.
    const token = await ftv.verifyJWT(jwt, true);

    expect(token).toStrictEqual(payload);
  });

  test.each([
    [
      'aud',
      {
        ...payload,
        aud: 'unknown',
      },
      'has incorrect "aud" (audience) claim.',
    ],
    [
      'iss',
      {
        ...payload,
        iss: projectId, // set just projectId
      },
      'has incorrect "iss" (issuer) claim.',
    ],
    [
      'sub',
      {
        ...payload,
        sub: 'x'.repeat(129),
      },
      'has "sub" (subject) claim longer than 128 characters.',
    ],
    [
      'auth_time',
      {
        ...payload,
        auth_time: undefined,
      },
      'has no "auth_time" claim.',
    ],
    [
      'auth_time is in future',
      {
        ...payload,
        auth_time: currentTimestamp + 3000, // +3s
      },
      'has incorrect "auth_time" claim.',
    ],
  ])('invalid verifyPayload %s', async (_, payload, wantContainMsg) => {
    const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration(kid);
    const jwt = await signJWT(kid, payload, testingKeyFetcher.getPrivateKey());

    const verifier = new PublicKeySignatureVerifier(testingKeyFetcher);
    const ftv = createFirebaseTokenVerifier(verifier, projectId);
    expect(() => ftv.verifyJWT(jwt, false)).rejects.toThrowError(wantContainMsg);
  });
});
