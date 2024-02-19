import type { Credential } from '../src';
import { encodeBase64Url, encodeObjectBase64Url } from '../src/base64';
import type { GoogleOAuthAccessToken } from '../src/credential';
import type { EmulatorEnv } from '../src/emulator';
import { emulatorHost } from '../src/emulator';
import { AuthClientErrorCode, FirebaseAuthError } from '../src/errors';
import { PublicKeySignatureVerifier } from '../src/jws-verifier';
import { FIREBASE_AUDIENCE, type FirebaseIdToken } from '../src/token-verifier';
import { utf8Encoder } from '../src/utf8';
import { isNonEmptyString, isNonNullObject } from '../src/validator';
import { signJWT, genTime, genIss, TestingKeyFetcher } from './jwk-utils';

export const projectId = 'project12345'; // see package.json
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

/**
 * CryptoSigner interface represents an object that can be used to sign JWTs.
 */
interface CryptoSigner {
  /**
   * The name of the signing algorithm.
   */
  readonly algorithm: Algorithm;

  /**
   * Cryptographically signs a buffer of data.
   *
   * @param buffer - The data to be signed.
   * @returns A promise that resolves with the raw bytes of a signature.
   */
  sign(buffer: Uint8Array): Promise<Uint8Array>;

  /**
   * Returns the ID of the service account used to sign tokens.
   *
   * @returns A promise that resolves with a service account ID.
   */
  getAccountId(): Promise<string>;
}

// List of blacklisted claims which cannot be provided when creating a custom token
const BLACKLISTED_CLAIMS = [
  'acr',
  'amr',
  'at_hash',
  'aud',
  'auth_time',
  'azp',
  'cnf',
  'c_hash',
  'exp',
  'iat',
  'iss',
  'jti',
  'nbf',
  'nonce',
];

/**
 * A CryptoSigner implementation that is used when communicating with the Auth emulator.
 * It produces unsigned tokens.
 */
export class EmulatedSigner implements CryptoSigner {
  public algorithm = {
    name: 'none',
  };
  /**
   * @inheritDoc
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async sign(buffer: Uint8Array): Promise<Uint8Array> {
    return utf8Encoder.encode('');
  }

  /**
   * @inheritDoc
   */
  public async getAccountId(): Promise<string> {
    return 'firebase-auth-emulator@example.com';
  }
}

export class FirebaseTokenGenerator {
  private readonly signer: CryptoSigner;

  constructor(signer: CryptoSigner) {
    if (!isNonNullObject(signer)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_CREDENTIAL,
        'INTERNAL ASSERT: Must provide a CryptoSigner to use FirebaseTokenGenerator.'
      );
    }
    this.signer = signer;
  }

  /**
   * Creates a new Firebase Auth Custom token.
   *
   * @param uid - The user ID to use for the generated Firebase Auth Custom token.
   * @param developerClaims - Optional developer claims to include in the generated Firebase
   *     Auth Custom token.
   * @returns A Promise fulfilled with a Firebase Auth Custom token signed with a
   *     service account key and containing the provided payload.
   */
  public async createCustomToken(uid: string, developerClaims?: { [key: string]: any }): Promise<string> {
    let errorMessage: string | undefined;
    if (!isNonEmptyString(uid)) {
      errorMessage = '`uid` argument must be a non-empty string uid.';
    } else if (uid.length > 128) {
      errorMessage = '`uid` argument must a uid with less than or equal to 128 characters.';
    } else if (!this.isDeveloperClaimsValid_(developerClaims)) {
      errorMessage = '`developerClaims` argument must be a valid, non-null object containing the developer claims.';
    }

    if (errorMessage) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_ARGUMENT, errorMessage);
    }

    const claims: { [key: string]: any } = {};
    if (typeof developerClaims !== 'undefined') {
      for (const key in developerClaims) {
        /* istanbul ignore else */
        if (Object.prototype.hasOwnProperty.call(developerClaims, key)) {
          if (BLACKLISTED_CLAIMS.indexOf(key) !== -1) {
            throw new FirebaseAuthError(
              AuthClientErrorCode.INVALID_ARGUMENT,
              `Developer claim "${key}" is reserved and cannot be specified.`
            );
          }
          claims[key] = developerClaims[key];
        }
      }
    }
    const account = await this.signer.getAccountId();
    const header = {
      alg: this.signer.algorithm,
      typ: 'JWT',
    };
    const iat = Math.floor(Date.now() / 1000);
    const body: Omit<FirebaseIdToken, 'firebase' | 'auth_time'> = {
      aud: FIREBASE_AUDIENCE,
      iat,
      exp: iat + 3600,
      iss: account,
      sub: account,
      uid,
    };
    if (Object.keys(claims).length > 0) {
      body.claims = claims;
    }
    const token = `${encodeObjectBase64Url(header)}.${encodeObjectBase64Url(body)}`.replace(/=/g, '');
    const signature = await this.signer.sign(utf8Encoder.encode(token));
    const base64Signature = encodeBase64Url(signature).replace(/=/g, '');
    return `${token}.${base64Signature}`;
  }

  /**
   * Returns whether or not the provided developer claims are valid.
   *
   * @param developerClaims - Optional developer claims to validate.
   * @returns True if the provided claims are valid; otherwise, false.
   */
  // eslint-disable-next-line @typescript-eslint/naming-convention
  private isDeveloperClaimsValid_(developerClaims?: object): boolean {
    if (typeof developerClaims === 'undefined') {
      return true;
    }
    return isNonNullObject(developerClaims);
  }
}

interface signInWithCustomTokenResponse {
  kind: string; // deprecated
  idToken: string;
  refreshToken: string;
  expiresIn: string; // int64 format
  isNewUser: boolean;
}

export async function signInWithCustomToken(
  customToken: string,
  env?: EmulatorEnv
): Promise<signInWithCustomTokenResponse> {
  const host = emulatorHost(env);
  if (!isNonEmptyString(host)) {
    throw new Error('unexpected emulator host is empty');
  }
  const signInPath = '/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=test1234';
  const firebaseEmulatorSignInUrl = 'http://' + host + signInPath;
  const res = await fetch(firebaseEmulatorSignInUrl, {
    method: 'POST',
    body: JSON.stringify({
      token: customToken,
      returnSecureToken: true,
    }),
    headers: {
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) {
    throw new Error(res.statusText);
  }
  const json = await res.json();
  return json as signInWithCustomTokenResponse;
}

export class NopCredential implements Credential {
  getAccessToken(): Promise<GoogleOAuthAccessToken> {
    return Promise.resolve({
      access_token: 'owner',
      expires_in: 9 * 3600,
    });
  }
}
