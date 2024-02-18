import { PublicKeySignatureVerifier } from '../src/jws-verifier';
import type { FirebaseIdToken } from '../src/token-verifier';
import { signJWT, genTime, genIss, TestingKeyFetcher } from './jwk-utils';

export const projectId = 'projectId1234';
export const userId = 'userId12345';

export async function generateIdToken(
  currentTimestamp?: number,
  overrides?: Partial<FirebaseIdToken>
): Promise<FirebaseIdToken> {
  const now = currentTimestamp ?? genTime(Date.now());
  return Object.assign(
    {
      aud: projectId,
      exp: now + 9999,
      iat: now - 10000, // -10s
      iss: genIss(projectId),
      sub: userId,
      auth_time: now - 20000, // -20s
      uid: userId,
      firebase: {
        identities: {},
        sign_in_provider: 'google.com',
      },
    } satisfies FirebaseIdToken,
    overrides
  );
}

export async function generateSessionCookie(
  currentTimestamp?: number,
  overrides?: Partial<FirebaseIdToken>
): Promise<FirebaseIdToken> {
  const now = currentTimestamp ?? genTime(Date.now());
  return Object.assign(
    {
      aud: projectId,
      exp: now + 9999,
      iat: now - 10000, // -10s
      iss: 'https://session.firebase.google.com/' + projectId,
      sub: userId,
      auth_time: now - 20000, // -20s
      uid: userId,
      firebase: {
        identities: {},
        sign_in_provider: 'google.com',
      },
    } satisfies FirebaseIdToken,
    overrides
  );
}

interface SignVerifyPair {
  jwt: string;
  verifier: PublicKeySignatureVerifier;
}

export async function createTestingSignVerifyPair(payload: FirebaseIdToken): Promise<SignVerifyPair> {
  const kid = 'aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd';
  const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration(kid);
  const jwt = await signJWT(kid, payload, testingKeyFetcher.getPrivateKey());
  return {
    jwt,
    verifier: new PublicKeySignatureVerifier(testingKeyFetcher),
  };
}
