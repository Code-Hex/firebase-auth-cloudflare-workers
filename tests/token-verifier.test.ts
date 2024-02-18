import { describe, it, expect } from 'vitest';
import { PublicKeySignatureVerifier, rs256alg } from '../src/jws-verifier';
import { FIREBASE_AUDIENCE, baseCreateIdTokenVerifier, baseCreateSessionCookieVerifier } from '../src/token-verifier';
import { createTestingSignVerifyPair, generateIdToken, generateSessionCookie, projectId } from './firebase-utils';
import { genTime, signJWT, TestingKeyFetcher } from './jwk-utils';

describe('FirebaseTokenVerifier', () => {
  const testCases = [
    {
      name: 'createIdTokenVerifier',
      tokenGenerator: generateIdToken,
      firebaseTokenVerifier: baseCreateIdTokenVerifier,
    },
    {
      name: 'createSessionCookieVerifier',
      tokenGenerator: generateSessionCookie,
      firebaseTokenVerifier: baseCreateSessionCookieVerifier,
    },
  ];
  for (const tc of testCases) {
    describe(tc.name, () => {
      const currentTimestamp = genTime(Date.now());

      it.each([
        ['valid without firebase emulator', tc.tokenGenerator(currentTimestamp)],
        [
          'valid custom token without firebase emulator',
          tc.tokenGenerator(currentTimestamp, { aud: FIREBASE_AUDIENCE }),
        ],
      ])('%s', async (_, promise) => {
        const payload = await promise;
        const pair = await createTestingSignVerifyPair(payload);
        const ftv = tc.firebaseTokenVerifier(pair.verifier, projectId);
        const token = await ftv.verifyJWT(pair.jwt, false);

        expect(token).toStrictEqual(payload);
      });

      it.each([
        ['aud', tc.tokenGenerator(currentTimestamp, { aud: 'unknown' }), 'has incorrect "aud" (audience) claim.'],
        [
          'iss',
          tc.tokenGenerator(currentTimestamp, {
            iss: projectId, // set just projectId
          }),
          'has incorrect "iss" (issuer) claim.',
        ],
        [
          'sub',
          tc.tokenGenerator(currentTimestamp, {
            sub: 'x'.repeat(129),
          }),
          'has "sub" (subject) claim longer than 128 characters.',
        ],
        [
          'auth_time',
          tc.tokenGenerator(currentTimestamp, {
            auth_time: undefined,
          }),
          'has no "auth_time" claim.',
        ],
        [
          'auth_time is in future',
          tc.tokenGenerator(currentTimestamp, {
            auth_time: currentTimestamp + 3000, // +3s
          }),
          'has incorrect "auth_time" claim.',
        ],
      ])('invalid verifyPayload %s', async (_, promise, wantContainMsg) => {
        const payload = await promise;
        const pair = await createTestingSignVerifyPair(payload);
        const ftv = tc.firebaseTokenVerifier(pair.verifier, projectId);
        expect(() => ftv.verifyJWT(pair.jwt, false)).rejects.toThrowError(wantContainMsg);
      });

      it('valid with firebase emulator', async () => {
        const payload = await tc.tokenGenerator(currentTimestamp);
        const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration('valid-kid');

        // sign as invalid private key with fetched public key
        const keyPair = await crypto.subtle.generateKey(rs256alg, true, ['sign', 'verify']);

        // set with invalid kid because jwt does not contain kid which issued from firebase emulator.
        const jwt = await signJWT('invalid-kid', payload, keyPair.privateKey);

        const verifier = new PublicKeySignatureVerifier(testingKeyFetcher);
        const ftv = tc.firebaseTokenVerifier(verifier, projectId);

        // firebase emulator ignores signature verification step.
        const token = await ftv.verifyJWT(jwt, true);

        expect(token).toStrictEqual(payload);
      });
    });
  }
});
