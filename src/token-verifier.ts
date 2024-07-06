import type { ErrorInfo } from './errors';
import { AuthClientErrorCode, FirebaseAuthError, JwtError, JwtErrorCode } from './errors';
import type { SignatureVerifier } from './jws-verifier';
import { EmulatorSignatureVerifier, PublicKeySignatureVerifier } from './jws-verifier';
import type { DecodedPayload } from './jwt-decoder';
import { RS256Token } from './jwt-decoder';
import type { KeyStorer } from './key-store';
import { isNonEmptyString, isNonNullObject, isString, isURL } from './validator';

// Audience to use for Firebase Auth Custom tokens
export const FIREBASE_AUDIENCE =
  'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';

const EMULATOR_VERIFIER = new EmulatorSignatureVerifier();

/**
 * Interface representing a decoded Firebase ID token, returned from the
 * {@link BaseAuth.verifyIdToken} method.
 *
 * Firebase ID tokens are OpenID Connect spec-compliant JSON Web Tokens (JWTs).
 * See the
 * [ID Token section of the OpenID Connect spec](http://openid.net/specs/openid-connect-core-1_0.html#IDToken)
 * for more information about the specific properties below.
 */
export interface FirebaseIdToken {
  /**
   * The audience for which this token is intended.
   *
   * This value is a string equal to your Firebase project ID, the unique
   * identifier for your Firebase project, which can be found in [your project's
   * settings](https://console.firebase.google.com/project/_/settings/general/android:com.random.android).
   */
  aud: string;

  /**
   * Time, in seconds since the Unix epoch, when the end-user authentication
   * occurred.
   *
   * This value is not set when this particular ID token was created, but when the
   * user initially logged in to this session. In a single session, the Firebase
   * SDKs will refresh a user's ID tokens every hour. Each ID token will have a
   * different [`iat`](#iat) value, but the same `auth_time` value.
   */
  auth_time: number;

  /**
   * The email of the user to whom the ID token belongs, if available.
   */
  email?: string;

  /**
   * Whether or not the email of the user to whom the ID token belongs is
   * verified, provided the user has an email.
   */
  email_verified?: boolean;

  /**
   * The ID token's expiration time, in seconds since the Unix epoch. That is, the
   * time at which this ID token expires and should no longer be considered valid.
   *
   * The Firebase SDKs transparently refresh ID tokens every hour, issuing a new
   * ID token with up to a one hour expiration.
   */
  exp: number;

  /**
   * Information about the sign in event, including which sign in provider was
   * used and provider-specific identity details.
   *
   * This data is provided by the Firebase Authentication service and is a
   * reserved claim in the ID token.
   */
  firebase: {
    /**
     * Provider-specific identity details corresponding
     * to the provider used to sign in the user.
     */
    identities: {
      [key: string]: any;
    };

    /**
     * The ID of the provider used to sign in the user.
     * One of `"anonymous"`, `"password"`, `"facebook.com"`, `"github.com"`,
     * `"google.com"`, `"twitter.com"`, `"apple.com"`, `"microsoft.com"`,
     * `"yahoo.com"`, `"phone"`, `"playgames.google.com"`, `"gc.apple.com"`,
     * or `"custom"`.
     *
     * Additional Identity Platform provider IDs include `"linkedin.com"`,
     * OIDC and SAML identity providers prefixed with `"saml."` and `"oidc."`
     * respectively.
     */
    sign_in_provider: string;

    /**
     * The type identifier or `factorId` of the second factor, provided the
     * ID token was obtained from a multi-factor authenticated user.
     * For phone, this is `"phone"`.
     */
    sign_in_second_factor?: string;

    /**
     * The `uid` of the second factor used to sign in, provided the
     * ID token was obtained from a multi-factor authenticated user.
     */
    second_factor_identifier?: string;

    /**
     * The ID of the tenant the user belongs to, if available.
     */
    tenant?: string;
    [key: string]: any;
  };

  /**
   * The ID token's issued-at time, in seconds since the Unix epoch. That is, the
   * time at which this ID token was issued and should start to be considered
   * valid.
   *
   * The Firebase SDKs transparently refresh ID tokens every hour, issuing a new
   * ID token with a new issued-at time. If you want to get the time at which the
   * user session corresponding to the ID token initially occurred, see the
   * [`auth_time`](#auth_time) property.
   */
  iat: number;

  /**
   * The issuer identifier for the issuer of the response.
   *
   * This value is a URL with the format
   * `https://securetoken.google.com/<PROJECT_ID>`, where `<PROJECT_ID>` is the
   * same project ID specified in the [`aud`](#aud) property.
   */
  iss: string;

  /**
   * The phone number of the user to whom the ID token belongs, if available.
   */
  phone_number?: string;

  /**
   * The photo URL for the user to whom the ID token belongs, if available.
   */
  picture?: string;

  /**
   * The `uid` corresponding to the user who the ID token belonged to.
   *
   * As a convenience, this value is copied over to the [`uid`](#uid) property.
   */
  sub: string;

  /**
   * The `uid` corresponding to the user who the ID token belonged to.
   *
   * This value is not actually in the JWT token claims itself. It is added as a
   * convenience, and is set as the value of the [`sub`](#sub) property.
   */
  uid: string;

  /**
   * Other arbitrary claims included in the ID token.
   */
  [key: string]: any;
}

const makeExpectedbutGotMsg = (want: any, got: any) => `Expected "${want}" but got "${got}".`;

/**
 * Class for verifying general purpose Firebase JWTs. This verifies ID tokens and session cookies.
 *
 * @internal
 */
export class FirebaseTokenVerifier {
  private readonly shortNameArticle: string;

  constructor(
    private readonly signatureVerifier: SignatureVerifier,
    private projectId: string,
    private issuer: string,
    private tokenInfo: FirebaseTokenInfo
  ) {
    if (!isNonEmptyString(projectId)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'Your Firebase project ID must be a non-empty string'
      );
    } else if (!isURL(issuer)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_ARGUMENT, 'The provided JWT issuer is an invalid URL.');
    } else if (!isNonNullObject(tokenInfo)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'The provided JWT information is not an object or null.'
      );
    } else if (!isURL(tokenInfo.url)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'The provided JWT verification documentation URL is invalid.'
      );
    } else if (!isNonEmptyString(tokenInfo.verifyApiName)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'The JWT verify API name must be a non-empty string.'
      );
    } else if (!isNonEmptyString(tokenInfo.jwtName)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'The JWT public full name must be a non-empty string.'
      );
    } else if (!isNonEmptyString(tokenInfo.shortName)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'The JWT public short name must be a non-empty string.'
      );
    } else if (!isNonNullObject(tokenInfo.expiredErrorCode) || !('code' in tokenInfo.expiredErrorCode)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'The JWT expiration error code must be a non-null ErrorInfo object.'
      );
    }
    this.shortNameArticle = tokenInfo.shortName.charAt(0).match(/[aeiou]/i) ? 'an' : 'a';
  }

  /**
   * Verifies the format and signature of a Firebase Auth JWT token.
   *
   * @param jwtToken - The Firebase Auth JWT token to verify.
   * @param isEmulator - Whether to accept Auth Emulator tokens.
   * @param clockSkewSeconds - The number of seconds to tolerate when checking the token's iat. Must be between 0-60, and an integer. Defualts to 0.
   * @returns A promise fulfilled with the decoded claims of the Firebase Auth ID token.
   */
  public verifyJWT(jwtToken: string, isEmulator = false, clockSkewSeconds: number = 0): Promise<FirebaseIdToken> {
    if (!isString(jwtToken)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        `First argument to ${this.tokenInfo.verifyApiName} must be a ${this.tokenInfo.jwtName} string.`
      );
    }

    if (clockSkewSeconds < 0 || clockSkewSeconds > 60 || !Number.isInteger(clockSkewSeconds)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'clockSkewSeconds must be an integer between 0 and 60.'
      )
    }
    return this.decodeAndVerify(jwtToken, isEmulator, 0).then(payload => {
      payload.uid = payload.sub;
      return payload;
    });
  }

  private async decodeAndVerify(token: string, isEmulator: boolean, clockSkewSeconds: number = 0): Promise<FirebaseIdToken> {
    const currentTimestamp = Math.floor(Date.now() / 1000) + clockSkewSeconds;
    try {
      const rs256Token = this.safeDecode(token, isEmulator, currentTimestamp);
      const { payload } = rs256Token.decodedToken;

      this.verifyPayload(payload, currentTimestamp);
      await this.verifySignature(rs256Token, isEmulator);

      return payload;
    } catch (err) {
      if (err instanceof JwtError) {
        throw this.mapJwtErrorToAuthError(err);
      }
      throw err;
    }
  }

  private safeDecode(jwtToken: string, isEmulator: boolean, currentTimestamp: number): RS256Token {
    try {
      return RS256Token.decode(jwtToken, currentTimestamp, isEmulator);
    } catch (err) {
      const verifyJwtTokenDocsMessage =
        ` See ${this.tokenInfo.url} ` +
        `for details on how to retrieve ${this.shortNameArticle} ${this.tokenInfo.shortName}.`;
      const errorMessage =
        `Decoding ${this.tokenInfo.jwtName} failed. Make sure you passed ` +
        `the entire string JWT which represents ${this.shortNameArticle} ` +
        `${this.tokenInfo.shortName}.` +
        verifyJwtTokenDocsMessage;
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_ARGUMENT, errorMessage + ` err: ${err}`);
    }
  }

  private verifyPayload(
    tokenPayload: DecodedPayload,
    currentTimestamp: number
  ): asserts tokenPayload is FirebaseIdToken {
    const payload = tokenPayload;

    const projectIdMatchMessage =
      ` Make sure the ${this.tokenInfo.shortName} comes from the same ` +
      'Firebase project as the service account used to authenticate this SDK.';
    const verifyJwtTokenDocsMessage =
      ` See ${this.tokenInfo.url} ` +
      `for details on how to retrieve ${this.shortNameArticle} ${this.tokenInfo.shortName}.`;

    const createInvalidArgument = (errorMessage: string) =>
      new FirebaseAuthError(AuthClientErrorCode.INVALID_ARGUMENT, errorMessage);

    if (payload.aud !== this.projectId && payload.aud !== FIREBASE_AUDIENCE) {
      throw createInvalidArgument(
        `${this.tokenInfo.jwtName} has incorrect "aud" (audience) claim. ` +
          makeExpectedbutGotMsg(this.projectId, payload.aud) +
          projectIdMatchMessage +
          verifyJwtTokenDocsMessage
      );
    }

    if (payload.iss !== this.issuer + this.projectId) {
      throw createInvalidArgument(
        `${this.tokenInfo.jwtName} has incorrect "iss" (issuer) claim. ` +
          makeExpectedbutGotMsg(this.issuer, payload.iss) +
          projectIdMatchMessage +
          verifyJwtTokenDocsMessage
      );
    }

    if (payload.sub.length > 128) {
      throw createInvalidArgument(
        `${this.tokenInfo.jwtName} has "sub" (subject) claim longer than 128 characters.` + verifyJwtTokenDocsMessage
      );
    }

    // check auth_time claim
    if (typeof payload.auth_time !== 'number') {
      throw createInvalidArgument(`${this.tokenInfo.jwtName} has no "auth_time" claim. ` + verifyJwtTokenDocsMessage);
    }

    if (currentTimestamp < payload.auth_time) {
      throw createInvalidArgument(
        `${this.tokenInfo.jwtName} has incorrect "auth_time" claim. ` + verifyJwtTokenDocsMessage
      );
    }
  }

  private async verifySignature(token: RS256Token, isEmulator: boolean): Promise<void> {
    const verifier = isEmulator ? EMULATOR_VERIFIER : this.signatureVerifier;
    return await verifier.verify(token);
  }

  /**
   * Maps JwtError to FirebaseAuthError
   *
   * @param error - JwtError to be mapped.
   * @returns FirebaseAuthError or Error instance.
   */
  private mapJwtErrorToAuthError(error: JwtError): Error {
    const verifyJwtTokenDocsMessage =
      ` See ${this.tokenInfo.url} ` +
      `for details on how to retrieve ${this.shortNameArticle} ${this.tokenInfo.shortName}.`;
    if (error.code === JwtErrorCode.TOKEN_EXPIRED) {
      const errorMessage =
        `${this.tokenInfo.jwtName} has expired. Get a fresh ${this.tokenInfo.shortName}` +
        ` from your client app and try again (auth/${this.tokenInfo.expiredErrorCode.code}).` +
        verifyJwtTokenDocsMessage;
      return new FirebaseAuthError(this.tokenInfo.expiredErrorCode, errorMessage);
    } else if (error.code === JwtErrorCode.INVALID_SIGNATURE) {
      const errorMessage = `${this.tokenInfo.jwtName} has invalid signature.` + verifyJwtTokenDocsMessage;
      return new FirebaseAuthError(AuthClientErrorCode.INVALID_ARGUMENT, errorMessage);
    } else if (error.code === JwtErrorCode.NO_MATCHING_KID) {
      const errorMessage =
        `${this.tokenInfo.jwtName} has "kid" claim which does not ` +
        `correspond to a known public key. Most likely the ${this.tokenInfo.shortName} ` +
        'is expired, so get a fresh token from your client app and try again.';
      return new FirebaseAuthError(AuthClientErrorCode.INVALID_ARGUMENT, errorMessage);
    }
    return new FirebaseAuthError(AuthClientErrorCode.INVALID_ARGUMENT, error.message);
  }
}

// URL containing the public keys for the Google certs (whose private keys are used to sign Firebase
// Auth ID tokens)
const CLIENT_JWK_URL = 'https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com';

/**
 * Interface that defines token related user facing information.
 *
 * @internal
 */
export interface FirebaseTokenInfo {
  /** Documentation URL. */
  url: string;
  /** verify API name. */
  verifyApiName: string;
  /** The JWT full name. */
  jwtName: string;
  /** The JWT short name. */
  shortName: string;
  /** JWT Expiration error code. */
  expiredErrorCode: ErrorInfo;
}

/**
 * User facing token information related to the Firebase ID token.
 *
 * @internal
 */
export const ID_TOKEN_INFO: FirebaseTokenInfo = {
  url: 'https://firebase.google.com/docs/auth/admin/verify-id-tokens',
  verifyApiName: 'verifyIdToken()',
  jwtName: 'Firebase ID token',
  shortName: 'ID token',
  expiredErrorCode: AuthClientErrorCode.ID_TOKEN_EXPIRED,
};

/**
 * Creates a new FirebaseTokenVerifier to verify Firebase ID tokens.
 *
 * @internal
 * @returns FirebaseTokenVerifier
 */
export function createIdTokenVerifier(projectID: string, keyStorer: KeyStorer): FirebaseTokenVerifier {
  const signatureVerifier = PublicKeySignatureVerifier.withCertificateUrl(CLIENT_JWK_URL, keyStorer);
  return baseCreateIdTokenVerifier(signatureVerifier, projectID);
}

/**
 * @internal
 * @returns FirebaseTokenVerifier
 */
export function baseCreateIdTokenVerifier(
  signatureVerifier: SignatureVerifier,
  projectID: string
): FirebaseTokenVerifier {
  return new FirebaseTokenVerifier(signatureVerifier, projectID, 'https://securetoken.google.com/', ID_TOKEN_INFO);
}

// URL containing the public keys for Firebase session cookies.
const SESSION_COOKIE_CERT_URL = 'https://identitytoolkit.googleapis.com/v1/sessionCookiePublicKeys';

/**
 * User facing token information related to the Firebase session cookie.
 *
 * @internal
 */
export const SESSION_COOKIE_INFO: FirebaseTokenInfo = {
  url: 'https://firebase.google.com/docs/auth/admin/manage-cookies',
  verifyApiName: 'verifySessionCookie()',
  jwtName: 'Firebase session cookie',
  shortName: 'session cookie',
  expiredErrorCode: AuthClientErrorCode.SESSION_COOKIE_EXPIRED,
};

/**
 * Creates a new FirebaseTokenVerifier to verify Firebase session cookies.
 *
 * @internal
 * @param app - Firebase app instance.
 * @returns FirebaseTokenVerifier
 */
export function createSessionCookieVerifier(projectID: string, keyStorer: KeyStorer): FirebaseTokenVerifier {
  const signatureVerifier = PublicKeySignatureVerifier.withCertificateUrl(SESSION_COOKIE_CERT_URL, keyStorer);
  return baseCreateSessionCookieVerifier(signatureVerifier, projectID);
}

/**
 * @internal
 * @returns FirebaseTokenVerifier
 */
export function baseCreateSessionCookieVerifier(
  signatureVerifier: SignatureVerifier,
  projectID: string
): FirebaseTokenVerifier {
  return new FirebaseTokenVerifier(
    signatureVerifier,
    projectID,
    'https://session.firebase.google.com/',
    SESSION_COOKIE_INFO
  );
}
