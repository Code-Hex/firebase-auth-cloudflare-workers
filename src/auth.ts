import { AuthApiClient } from './auth-api-requests';
import type { Credential } from './credential';
import type { EmulatorEnv } from './emulator';
import { useEmulator } from './emulator';
import type { ErrorInfo } from './errors';
import { AppErrorCodes, AuthClientErrorCode, FirebaseAppError, FirebaseAuthError } from './errors';
import type { KeyStorer } from './key-store';
import type { FirebaseIdToken, FirebaseTokenVerifier } from './token-verifier';
import { createIdTokenVerifier, createSessionCookieVerifier } from './token-verifier';
import type { UserRecord } from './user-record';
import { isNonNullObject, isNumber } from './validator';

export class BaseAuth {
  /** @internal */
  protected readonly idTokenVerifier: FirebaseTokenVerifier;
  protected readonly sessionCookieVerifier: FirebaseTokenVerifier;
  private readonly _authApiClient?: AuthApiClient;

  constructor(projectId: string, keyStore: KeyStorer, credential?: Credential) {
    this.idTokenVerifier = createIdTokenVerifier(projectId, keyStore);
    this.sessionCookieVerifier = createSessionCookieVerifier(projectId, keyStore);

    if (credential) {
      this._authApiClient = new AuthApiClient(projectId, credential);
    }
  }

  private get authApiClient(): AuthApiClient {
    if (this._authApiClient) {
      return this._authApiClient;
    }
    throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, 'Service account must be required in initialization.');
  }

  /**
   * Verifies a Firebase ID token (JWT). If the token is valid, the promise is
   * fulfilled with the token's decoded claims; otherwise, the promise is
   * rejected.
   *
   * If `checkRevoked` is set to true, first verifies whether the corresponding
   * user is disabled. If yes, an `auth/user-disabled` error is thrown. If no,
   * verifies if the session corresponding to the ID token was revoked. If the
   * corresponding user's session was invalidated, an `auth/id-token-revoked`
   * error is thrown. If not specified the check is not applied.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/verify-id-tokens | Verify ID Tokens}
   * for code samples and detailed documentation.
   *
   * @param idToken - The ID token to verify.
   * @param checkRevoked - Whether to check if the ID token was revoked.
   *   This requires an extra request to the Firebase Auth backend to check
   *   the `tokensValidAfterTime` time for the corresponding user.
   *   When not specified, this additional check is not applied.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   * @param clockSkewSeconds - The number of seconds to tolerate when checking the `iat`.
   *   This is to deal with small clock differences among different servers.
   * @returns A promise fulfilled with the
   *   token's decoded claims if the ID token is valid; otherwise, a rejected
   *   promise.
   */
  public async verifyIdToken(
    idToken: string,
    checkRevoked = false,
    env?: EmulatorEnv,
    clockSkewSeconds?: number
  ): Promise<FirebaseIdToken> {
    const isEmulator = useEmulator(env);
    const decodedIdToken = await this.idTokenVerifier.verifyJWT(idToken, isEmulator, clockSkewSeconds);
    // Whether to check if the token was revoked.
    if (checkRevoked) {
      return await this.verifyDecodedJWTNotRevokedOrDisabled(decodedIdToken, AuthClientErrorCode.ID_TOKEN_REVOKED, env);
    }
    return decodedIdToken;
  }

  /**
   * Creates a new Firebase session cookie with the specified options. The created
   * JWT string can be set as a server-side session cookie with a custom cookie
   * policy, and be used for session management. The session cookie JWT will have
   * the same payload claims as the provided ID token.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/manage-cookies | Manage Session Cookies}
   * for code samples and detailed documentation.
   *
   * @param idToken - The Firebase ID token to exchange for a session
   *   cookie.
   * @param sessionCookieOptions - The session
   *   cookie options which includes custom session duration.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   *
   * @returns A promise that resolves on success with the
   *   created session cookie.
   */
  public async createSessionCookie(
    idToken: string,
    sessionCookieOptions: SessionCookieOptions,
    env?: EmulatorEnv
  ): Promise<string> {
    // Return rejected promise if expiresIn is not available.
    if (!isNonNullObject(sessionCookieOptions) || !isNumber(sessionCookieOptions.expiresIn)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_SESSION_COOKIE_DURATION);
    }
    return await this.authApiClient.createSessionCookie(idToken, sessionCookieOptions.expiresIn, env);
  }

  /**
   * Verifies a Firebase session cookie. Returns a Promise with the cookie claims.
   * Rejects the promise if the cookie could not be verified.
   *
   * If `checkRevoked` is set to true, first verifies whether the corresponding
   * user is disabled: If yes, an `auth/user-disabled` error is thrown. If no,
   * verifies if the session corresponding to the session cookie was revoked.
   * If the corresponding user's session was invalidated, an
   * `auth/session-cookie-revoked` error is thrown. If not specified the check
   * is not performed.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/manage-cookies#verify_session_cookie_and_check_permissions |
   * Verify Session Cookies}
   * for code samples and detailed documentation
   *
   * @param sessionCookie - The session cookie to verify.
   * @param checkRevoked -  Whether to check if the session cookie was
   *   revoked. This requires an extra request to the Firebase Auth backend to
   *   check the `tokensValidAfterTime` time for the corresponding user.
   *   When not specified, this additional check is not performed.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   *
   * @returns A promise fulfilled with the
   *   session cookie's decoded claims if the session cookie is valid; otherwise,
   *   a rejected promise.
   */
  public async verifySessionCookie(
    sessionCookie: string,
    checkRevoked = false,
    env?: EmulatorEnv
  ): Promise<FirebaseIdToken> {
    const isEmulator = useEmulator(env);
    const decodedIdToken = await this.sessionCookieVerifier.verifyJWT(sessionCookie, isEmulator);
    // Whether to check if the token was revoked.
    if (checkRevoked) {
      return await this.verifyDecodedJWTNotRevokedOrDisabled(
        decodedIdToken,
        AuthClientErrorCode.SESSION_COOKIE_REVOKED,
        env
      );
    }
    return decodedIdToken;
  }

  /**
   * Gets the user data for the user corresponding to a given `uid`.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/manage-users#retrieve_user_data | Retrieve user data}
   * for code samples and detailed documentation.
   *
   * @param uid - The `uid` corresponding to the user whose data to fetch.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   *
   * @returns A promise fulfilled with the user
   *   data corresponding to the provided `uid`.
   */
  public async getUser(uid: string, env?: EmulatorEnv): Promise<UserRecord> {
    return await this.authApiClient.getAccountInfoByUid(uid, env);
  }

  /**
   * Revokes all refresh tokens for an existing user.
   *
   * This API will update the user's {@link UserRecord.tokensValidAfterTime} to
   * the current UTC. It is important that the server on which this is called has
   * its clock set correctly and synchronized.
   *
   * While this will revoke all sessions for a specified user and disable any
   * new ID tokens for existing sessions from getting minted, existing ID tokens
   * may remain active until their natural expiration (one hour). To verify that
   * ID tokens are revoked, use {@link BaseAuth.verifyIdToken}
   * where `checkRevoked` is set to true.
   *
   * @param uid - The `uid` corresponding to the user whose refresh tokens
   *   are to be revoked.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   *
   * @returns An empty promise fulfilled once the user's refresh
   *   tokens have been revoked.
   */
  public async revokeRefreshTokens(uid: string, env?: EmulatorEnv): Promise<void> {
    await this.authApiClient.revokeRefreshTokens(uid, env);
  }

  /**
   * Sets additional developer claims on an existing user identified by the
   * provided `uid`, typically used to define user roles and levels of
   * access. These claims should propagate to all devices where the user is
   * already signed in (after token expiration or when token refresh is forced)
   * and the next time the user signs in. If a reserved OIDC claim name
   * is used (sub, iat, iss, etc), an error is thrown. They are set on the
   * authenticated user's ID token JWT.
   *
   * See {@link https://firebase.google.com/docs/auth/admin/custom-claims |
   * Defining user roles and access levels}
   * for code samples and detailed documentation.
   *
   * @param uid - The `uid` of the user to edit.
   * @param customUserClaims - The developer claims to set. If null is
   *   passed, existing custom claims are deleted. Passing a custom claims payload
   *   larger than 1000 bytes will throw an error. Custom claims are added to the
   *   user's ID token which is transmitted on every authenticated request.
   *   For profile non-access related user attributes, use database or other
   *   separate storage systems.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   * @returns A promise that resolves when the operation completes
   *   successfully.
   */
  public async setCustomUserClaims(uid: string, customUserClaims: object | null, env?: EmulatorEnv): Promise<void> {
    await this.authApiClient.setCustomUserClaims(uid, customUserClaims, env);
  }

  /**
   * Verifies the decoded Firebase issued JWT is not revoked or disabled. Returns a promise that
   * resolves with the decoded claims on success. Rejects the promise with revocation error if revoked
   * or user disabled.
   *
   * @param decodedIdToken - The JWT's decoded claims.
   * @param revocationErrorInfo - The revocation error info to throw on revocation
   *     detection.
   * @returns A promise that will be fulfilled after a successful verification.
   */
  private async verifyDecodedJWTNotRevokedOrDisabled(
    decodedIdToken: FirebaseIdToken,
    revocationErrorInfo: ErrorInfo,
    env?: EmulatorEnv
  ): Promise<FirebaseIdToken> {
    // Get tokens valid after time for the corresponding user.
    const user = await this.getUser(decodedIdToken.sub, env);
    if (user.disabled) {
      throw new FirebaseAuthError(AuthClientErrorCode.USER_DISABLED, 'The user record is disabled.');
    }
    // If no tokens valid after time available, token is not revoked.
    if (user.tokensValidAfterTime) {
      // Get the ID token authentication time and convert to milliseconds UTC.
      const authTimeUtc = decodedIdToken.auth_time * 1000;
      // Get user tokens valid after time in milliseconds UTC.
      const validSinceUtc = new Date(user.tokensValidAfterTime).getTime();
      // Check if authentication time is older than valid since time.
      if (authTimeUtc < validSinceUtc) {
        throw new FirebaseAuthError(revocationErrorInfo);
      }
    }
    // All checks above passed. Return the decoded token.
    return decodedIdToken;
  }
}

/**
 * Interface representing the session cookie options needed for the
 * {@link BaseAuth.createSessionCookie} method.
 */
export interface SessionCookieOptions {
  /**
   * The session cookie custom expiration in milliseconds. The minimum allowed is
   * 5 minutes and the maxium allowed is 2 weeks.
   */
  expiresIn: number;
}
