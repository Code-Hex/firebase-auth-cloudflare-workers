import { ApiSettings } from './api-requests';
import { BaseClient } from './client';
import type { EmulatorEnv } from './emulator';
import { AuthClientErrorCode, FirebaseAuthError } from './errors';
import { UserRecord } from './user-record';
import { isNonEmptyString, isNumber, isObject, isUid } from './validator';

/** Minimum allowed session cookie duration in seconds (5 minutes). */
const MIN_SESSION_COOKIE_DURATION_SECS = 5 * 60;

/** Maximum allowed session cookie duration in seconds (2 weeks). */
const MAX_SESSION_COOKIE_DURATION_SECS = 14 * 24 * 60 * 60;

/** List of reserved claims which cannot be provided when creating a custom token. */
const RESERVED_CLAIMS = [
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
  'sub',
  'firebase',
];

/** Maximum allowed number of characters in the custom claims payload. */
const MAX_CLAIMS_PAYLOAD_SIZE = 1000;

/**
 * Instantiates the createSessionCookie endpoint settings.
 *
 * @internal
 */
export const FIREBASE_AUTH_CREATE_SESSION_COOKIE = new ApiSettings('v1', ':createSessionCookie', 'POST')
  // Set request validator.
  .setRequestValidator((request: any) => {
    // Validate the ID token is a non-empty string.
    if (!isNonEmptyString(request.idToken)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_ID_TOKEN);
    }
    // Validate the custom session cookie duration.
    if (
      !isNumber(request.validDuration) ||
      request.validDuration < MIN_SESSION_COOKIE_DURATION_SECS ||
      request.validDuration > MAX_SESSION_COOKIE_DURATION_SECS
    ) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_SESSION_COOKIE_DURATION);
    }
  })
  // Set response validator.
  .setResponseValidator((response: any) => {
    // Response should always contain the session cookie.
    if (!isNonEmptyString(response.sessionCookie)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INTERNAL_ERROR);
    }
  });

interface GetAccountInfoRequest {
  localId?: string[];
  email?: string[];
  phoneNumber?: string[];
  federatedUserId?: Array<{
    providerId: string;
    rawId: string;
  }>;
}

/**
 * Instantiates the getAccountInfo endpoint settings.
 *
 * @internal
 */
export const FIREBASE_AUTH_GET_ACCOUNT_INFO = new ApiSettings('v1', '/accounts:lookup', 'POST')
  // Set request validator.
  .setRequestValidator((request: GetAccountInfoRequest) => {
    if (!request.localId && !request.email && !request.phoneNumber && !request.federatedUserId) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INTERNAL_ERROR,
        'INTERNAL ASSERT FAILED: Server request is missing user identifier'
      );
    }
  })
  // Set response validator.
  .setResponseValidator((response: any) => {
    if (!response.users || !response.users.length) {
      throw new FirebaseAuthError(AuthClientErrorCode.USER_NOT_FOUND);
    }
  });

/**
 * Instantiates the revokeRefreshTokens endpoint settings for updating existing accounts.
 *
 * @internal
 * @link https://github.com/firebase/firebase-admin-node/blob/9955bca47249301aa970679ae99fe01d54adf6a8/src/auth/auth-api-request.ts#L746
 */
export const FIREBASE_AUTH_REVOKE_REFRESH_TOKENS = new ApiSettings('v1', '/accounts:update', 'POST')
  // Set request validator.
  .setRequestValidator((request: any) => {
    // localId is a required parameter.
    if (typeof request.localId === 'undefined') {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INTERNAL_ERROR,
        'INTERNAL ASSERT FAILED: Server request is missing user identifier'
      );
    }
    // validSince should be a number.
    if (typeof request.validSince !== 'undefined' && !isNumber(request.validSince)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_TOKENS_VALID_AFTER_TIME);
    }
  })
  // Set response validator.
  .setResponseValidator((response: any) => {
    // If the localId is not returned, then the request failed.
    if (!response.localId) {
      throw new FirebaseAuthError(AuthClientErrorCode.USER_NOT_FOUND);
    }
  });

/**
 * Instantiates the setCustomUserClaims endpoint settings for updating existing accounts.
 *
 * @internal
 * @link https://github.com/firebase/firebase-admin-node/blob/9955bca47249301aa970679ae99fe01d54adf6a8/src/auth/auth-api-request.ts#L746
 */
export const FIREBASE_AUTH_SET_CUSTOM_USER_CLAIMS = new ApiSettings('v1', '/accounts:update', 'POST')
  // Set request validator.
  .setRequestValidator((request: any) => {
    // localId is a required parameter.
    if (typeof request.localId === 'undefined') {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INTERNAL_ERROR,
        'INTERNAL ASSERT FAILED: Server request is missing user identifier'
      );
    }
    // customAttributes should be stringified JSON with no blacklisted claims.
    // The payload should not exceed 1KB.
    if (typeof request.customAttributes !== 'undefined') {
      let developerClaims: object;
      try {
        developerClaims = JSON.parse(request.customAttributes);
      } catch (error) {
        if (error instanceof Error) {
          // JSON parsing error. This should never happen as we stringify the claims internally.
          // However, we still need to check since setAccountInfo via edit requests could pass
          // this field.
          throw new FirebaseAuthError(AuthClientErrorCode.INVALID_CLAIMS, error.message);
        }
        throw error;
      }
      const invalidClaims: string[] = [];
      // Check for any invalid claims.
      RESERVED_CLAIMS.forEach(blacklistedClaim => {
        if (Object.prototype.hasOwnProperty.call(developerClaims, blacklistedClaim)) {
          invalidClaims.push(blacklistedClaim);
        }
      });
      // Throw an error if an invalid claim is detected.
      if (invalidClaims.length > 0) {
        throw new FirebaseAuthError(
          AuthClientErrorCode.FORBIDDEN_CLAIM,
          invalidClaims.length > 1
            ? `Developer claims "${invalidClaims.join('", "')}" are reserved and cannot be specified.`
            : `Developer claim "${invalidClaims[0]}" is reserved and cannot be specified.`
        );
      }
      // Check claims payload does not exceed maxmimum size.
      if (request.customAttributes.length > MAX_CLAIMS_PAYLOAD_SIZE) {
        throw new FirebaseAuthError(
          AuthClientErrorCode.CLAIMS_TOO_LARGE,
          `Developer claims payload should not exceed ${MAX_CLAIMS_PAYLOAD_SIZE} characters.`
        );
      }
    }
  })
  // Set response validator.
  .setResponseValidator((response: any) => {
    // If the localId is not returned, then the request failed.
    if (!response.localId) {
      throw new FirebaseAuthError(AuthClientErrorCode.USER_NOT_FOUND);
    }
  });

export class AuthApiClient extends BaseClient {
  /**
   * Creates a new Firebase session cookie with the specified duration that can be used for
   * session management (set as a server side session cookie with custom cookie policy).
   * The session cookie JWT will have the same payload claims as the provided ID token.
   *
   * @param idToken - The Firebase ID token to exchange for a session cookie.
   * @param expiresIn - The session cookie duration in milliseconds.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   *
   * @returns A promise that resolves on success with the created session cookie.
   */
  public async createSessionCookie(idToken: string, expiresIn: number, env?: EmulatorEnv): Promise<string> {
    const request = {
      idToken,
      // Convert to seconds.
      validDuration: expiresIn / 1000,
    };
    const res = await this.fetch<{ sessionCookie: string }>(FIREBASE_AUTH_CREATE_SESSION_COOKIE, request, env);
    return res.sessionCookie;
  }

  /**
   * Looks up a user by uid.
   *
   * @param uid - The uid of the user to lookup.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   * @returns A promise that resolves with the user information.
   */
  public async getAccountInfoByUid(uid: string, env?: EmulatorEnv): Promise<UserRecord> {
    if (!isUid(uid)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_UID);
    }

    const request = {
      localId: [uid],
    };
    const res = await this.fetch<object>(FIREBASE_AUTH_GET_ACCOUNT_INFO, request, env);
    // Returns the user record populated with server response.
    return new UserRecord((res as any).users[0]);
  }

  /**
   * Revokes all refresh tokens for the specified user identified by the uid provided.
   * In addition to revoking all refresh tokens for a user, all ID tokens issued
   * before revocation will also be revoked on the Auth backend. Any request with an
   * ID token generated before revocation will be rejected with a token expired error.
   * Note that due to the fact that the timestamp is stored in seconds, any tokens minted in
   * the same second as the revocation will still be valid. If there is a chance that a token
   * was minted in the last second, delay for 1 second before revoking.
   *
   * @param uid - The user whose tokens are to be revoked.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   * @returns A promise that resolves when the operation completes
   *     successfully with the user id of the corresponding user.
   */
  public async revokeRefreshTokens(uid: string, env?: EmulatorEnv): Promise<string> {
    // Validate user UID.
    if (!isUid(uid)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_UID);
    }
    const request: any = {
      localId: uid,
      // validSince is in UTC seconds.
      validSince: Math.floor(new Date().getTime() / 1000),
    };
    const res = await this.fetch<{ localId: string }>(FIREBASE_AUTH_REVOKE_REFRESH_TOKENS, request, env);
    return res.localId;
  }

  /**
   * Sets additional developer claims on an existing user identified by provided UID.
   *
   * @param uid - The user to edit.
   * @param customUserClaims - The developer claims to set.
   * @param env - An optional parameter specifying the environment in which the function is running.
   *   If the function is running in an emulator environment, this should be set to `EmulatorEnv`.
   *   If not specified, the function will assume it is running in a production environment.
   * @returns A promise that resolves when the operation completes
   *     with the user id that was edited.
   */
  public async setCustomUserClaims(uid: string, customUserClaims: object | null, env?: EmulatorEnv): Promise<string> {
    // Validate user UID.
    if (!isUid(uid)) {
      throw new FirebaseAuthError(AuthClientErrorCode.INVALID_UID);
    } else if (!isObject(customUserClaims)) {
      throw new FirebaseAuthError(
        AuthClientErrorCode.INVALID_ARGUMENT,
        'CustomUserClaims argument must be an object or null.'
      );
    }
    // Delete operation. Replace null with an empty object.
    if (customUserClaims === null) {
      customUserClaims = {};
    }
    // Construct custom user attribute editting request.
    const request: any = {
      localId: uid,
      customAttributes: JSON.stringify(customUserClaims),
    };
    const res = await this.fetch<{ localId: string }>(FIREBASE_AUTH_SET_CUSTOM_USER_CLAIMS, request, env);
    return res.localId;
  }
}
