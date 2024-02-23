/**
 * Jwt error code structure.
 *
 * @param code - The error code.
 * @param message - The error message.
 * @constructor
 */
export class JwtError extends Error {
  constructor(
    readonly code: JwtErrorCode,
    readonly message: string
  ) {
    super(message);
    (this as any).__proto__ = JwtError.prototype;
  }
}

/**
 * JWT error codes.
 */
export enum JwtErrorCode {
  INVALID_ARGUMENT = 'invalid-argument',
  INVALID_CREDENTIAL = 'invalid-credential',
  TOKEN_EXPIRED = 'token-expired',
  INVALID_SIGNATURE = 'invalid-token',
  NO_MATCHING_KID = 'no-matching-kid-error',
  NO_KID_IN_HEADER = 'no-kid-error',
  KEY_FETCH_ERROR = 'key-fetch-error',
}

/**
 * App client error codes and their default messages.
 */
export class AppErrorCodes {
  public static INVALID_CREDENTIAL = 'invalid-credential';
  public static INTERNAL_ERROR = 'internal-error';
  public static NETWORK_ERROR = 'network-error';
  public static NETWORK_TIMEOUT = 'network-timeout';
  public static UNABLE_TO_PARSE_RESPONSE = 'unable-to-parse-response';
}

/**
 * Auth client error codes and their default messages.
 */
export class AuthClientErrorCode {
  public static INVALID_ARGUMENT = {
    code: 'argument-error',
    message: 'Invalid argument provided.',
  };
  public static INVALID_CREDENTIAL = {
    code: 'invalid-credential',
    message: 'Invalid credential object provided.',
  };
  public static ID_TOKEN_EXPIRED = {
    code: 'id-token-expired',
    message: 'The provided Firebase ID token is expired.',
  };
  public static INVALID_ID_TOKEN = {
    code: 'invalid-id-token',
    message: 'The provided ID token is not a valid Firebase ID token.',
  };
  public static ID_TOKEN_REVOKED = {
    code: 'id-token-revoked',
    message: 'The Firebase ID token has been revoked.',
  };
  public static INTERNAL_ERROR = {
    code: 'internal-error',
    message: 'An internal error has occurred.',
  };
  public static USER_NOT_FOUND = {
    code: 'user-not-found',
    message: 'There is no user record corresponding to the provided identifier.',
  };
  public static USER_DISABLED = {
    code: 'user-disabled',
    message: 'The user record is disabled.',
  };
  public static SESSION_COOKIE_EXPIRED = {
    code: 'session-cookie-expired',
    message: 'The Firebase session cookie is expired.',
  };
  public static SESSION_COOKIE_REVOKED = {
    code: 'session-cookie-revoked',
    message: 'The Firebase session cookie has been revoked.',
  };
  public static INVALID_SESSION_COOKIE_DURATION = {
    code: 'invalid-session-cookie-duration',
    message: 'The session cookie duration must be a valid number in milliseconds ' + 'between 5 minutes and 2 weeks.',
  };
  public static INVALID_UID = {
    code: 'invalid-uid',
    message: 'The uid must be a non-empty string with at most 128 characters.',
  };
  public static INVALID_TOKENS_VALID_AFTER_TIME = {
    code: 'invalid-tokens-valid-after-time',
    message: 'The tokensValidAfterTime must be a valid UTC number in seconds.',
  };
  public static FORBIDDEN_CLAIM = {
    code: 'reserved-claim',
    message: 'The specified developer claim is reserved and cannot be specified.',
  };
  public static INVALID_CLAIMS = {
    code: 'invalid-claims',
    message: 'The provided custom claim attributes are invalid.',
  };
  public static CLAIMS_TOO_LARGE = {
    code: 'claims-too-large',
    message: 'Developer claims maximum payload size exceeded.',
  };
}

/**
 * `FirebaseErrorInterface` is a subclass of the standard JavaScript `Error` object. In
 * addition to a message string and stack trace, it contains a string code.
 */
export interface FirebaseErrorInterface {
  /**
   * Error codes are strings using the following format: `"service/string-code"`.
   * Some examples include `"auth/invalid-uid"` and
   * `"messaging/invalid-recipient"`.
   *
   * While the message for a given error can change, the code will remain the same
   * between backward-compatible versions of the Firebase SDK.
   */
  code: string;

  /**
   * An explanatory message for the error that just occurred.
   *
   * This message is designed to be helpful to you, the developer. Because
   * it generally does not convey meaningful information to end users,
   * this message should not be displayed in your application.
   */
  message: string;

  /**
   * A string value containing the execution backtrace when the error originally
   * occurred.
   *
   * This information can be useful for troubleshooting the cause of the error with
   * {@link https://firebase.google.com/support | Firebase Support}.
   */
  stack?: string;

  /**
   * Returns a JSON-serializable object representation of this error.
   *
   * @returns A JSON-serializable representation of this object.
   */
  toJSON(): object;
}

/**
 * Firebase error code structure. This extends Error.
 *
 * @param errorInfo - The error information (code and message).
 * @constructor
 */
export class FirebaseError extends Error implements FirebaseErrorInterface {
  constructor(private errorInfo: ErrorInfo) {
    super(errorInfo.message);

    /* tslint:disable:max-line-length */
    // Set the prototype explicitly. See the following link for more details:
    // https://github.com/Microsoft/TypeScript/wiki/Breaking-Changes#extending-built-ins-like-error-array-and-map-may-no-longer-work
    /* tslint:enable:max-line-length */
    (this as any).__proto__ = FirebaseError.prototype;
  }

  /** @returns The error code. */
  public get code(): string {
    return this.errorInfo.code;
  }

  /** @returns The error message. */
  public get message(): string {
    return this.errorInfo.message;
  }

  /** @returns The object representation of the error. */
  public toJSON(): object {
    return {
      code: this.code,
      message: this.message,
    };
  }
}

/**
 * Defines error info type. This includes a code and message string.
 */
export interface ErrorInfo {
  code: string;
  message: string;
}

/**
 * A FirebaseError with a prefix in front of the error code.
 *
 * @param codePrefix - The prefix to apply to the error code.
 * @param code - The error code.
 * @param message - The error message.
 * @constructor
 */
export class PrefixedFirebaseError extends FirebaseError {
  constructor(
    private codePrefix: string,
    code: string,
    message: string
  ) {
    super({
      code: `${codePrefix}/${code}`,
      message,
    });

    /* tslint:disable:max-line-length */
    // Set the prototype explicitly. See the following link for more details:
    // https://github.com/Microsoft/TypeScript/wiki/Breaking-Changes#extending-built-ins-like-error-array-and-map-may-no-longer-work
    /* tslint:enable:max-line-length */
    (this as any).__proto__ = PrefixedFirebaseError.prototype;
  }

  /**
   * Allows the error type to be checked without needing to know implementation details
   * of the code prefixing.
   *
   * @param code - The non-prefixed error code to test against.
   * @returns True if the code matches, false otherwise.
   */
  public hasCode(code: string): boolean {
    return `${this.codePrefix}/${code}` === this.code;
  }
}

/**
 * Firebase Auth error code structure. This extends PrefixedFirebaseError.
 *
 * @param info - The error code info.
 * @param [message] The error message. This will override the default
 *     message if provided.
 * @constructor
 */
export class FirebaseAuthError extends PrefixedFirebaseError {
  constructor(info: ErrorInfo, message?: string) {
    // Override default message if custom message provided.
    super('auth', info.code, message || info.message);

    /* tslint:disable:max-line-length */
    // Set the prototype explicitly. See the following link for more details:
    // https://github.com/Microsoft/TypeScript/wiki/Breaking-Changes#extending-built-ins-like-error-array-and-map-may-no-longer-work
    /* tslint:enable:max-line-length */
    (this as any).__proto__ = FirebaseAuthError.prototype;
  }

  /**
   * Creates the developer-facing error corresponding to the backend error code.
   *
   * @param serverErrorCode - The server error code.
   * @param [message] The error message. The default message is used
   *     if not provided.
   * @param [rawServerResponse] The error's raw server response.
   * @returns The corresponding developer-facing error.
   */
  public static fromServerError(serverErrorCode: string, rawServerResponse?: object): FirebaseAuthError {
    // serverErrorCode could contain additional details:
    // ERROR_CODE : Detailed message which can also contain colons
    const colonSeparator = (serverErrorCode || '').indexOf(':');
    if (colonSeparator !== -1) {
      serverErrorCode = serverErrorCode.substring(0, colonSeparator).trim();
    }
    // If not found, default to internal error.
    const clientCodeKey = AUTH_SERVER_TO_CLIENT_CODE[serverErrorCode] || 'INTERNAL_ERROR';
    const error: ErrorInfo = {
      ...AuthClientErrorCode.INTERNAL_ERROR,
      ...(AuthClientErrorCode as any)[clientCodeKey],
    };

    if (clientCodeKey === 'INTERNAL_ERROR' && typeof rawServerResponse !== 'undefined') {
      try {
        error.message += ` Raw server response: "${JSON.stringify(rawServerResponse)}"`;
      } catch (e) {
        // Ignore JSON parsing error.
      }
    }
    return new FirebaseAuthError(error);
  }
}

/**
 * Firebase App error code structure. This extends PrefixedFirebaseError.
 *
 * @param code - The error code.
 * @param message - The error message.
 * @constructor
 */
export class FirebaseAppError extends PrefixedFirebaseError {
  constructor(code: string, message: string) {
    super('app', code, message);

    /* tslint:disable:max-line-length */
    // Set the prototype explicitly. See the following link for more details:
    // https://github.com/Microsoft/TypeScript/wiki/Breaking-Changes#extending-built-ins-like-error-array-and-map-may-no-longer-work
    /* tslint:enable:max-line-length */
    (this as any).__proto__ = FirebaseAppError.prototype;
  }
}

/**
 * Defines a type that stores all server to client codes (string enum).
 */
interface ServerToClientCode {
  [code: string]: string;
}

/** @const {ServerToClientCode} Auth server to client enum error codes. */
const AUTH_SERVER_TO_CLIENT_CODE: ServerToClientCode = {
  // Feature being configured or used requires a billing account.
  BILLING_NOT_ENABLED: 'BILLING_NOT_ENABLED',
  // Claims payload is too large.
  CLAIMS_TOO_LARGE: 'CLAIMS_TOO_LARGE',
  // Configuration being added already exists.
  CONFIGURATION_EXISTS: 'CONFIGURATION_EXISTS',
  // Configuration not found.
  CONFIGURATION_NOT_FOUND: 'CONFIGURATION_NOT_FOUND',
  // Provided credential has insufficient permissions.
  INSUFFICIENT_PERMISSION: 'INSUFFICIENT_PERMISSION',
  // Provided configuration has invalid fields.
  INVALID_CONFIG: 'INVALID_CONFIG',
  // Provided configuration identifier is invalid.
  INVALID_CONFIG_ID: 'INVALID_PROVIDER_ID',
  // ActionCodeSettings missing continue URL.
  INVALID_CONTINUE_URI: 'INVALID_CONTINUE_URI',
  // Dynamic link domain in provided ActionCodeSettings is not authorized.
  INVALID_DYNAMIC_LINK_DOMAIN: 'INVALID_DYNAMIC_LINK_DOMAIN',
  // uploadAccount provides an email that already exists.
  DUPLICATE_EMAIL: 'EMAIL_ALREADY_EXISTS',
  // uploadAccount provides a localId that already exists.
  DUPLICATE_LOCAL_ID: 'UID_ALREADY_EXISTS',
  // Request specified a multi-factor enrollment ID that already exists.
  DUPLICATE_MFA_ENROLLMENT_ID: 'SECOND_FACTOR_UID_ALREADY_EXISTS',
  // setAccountInfo email already exists.
  EMAIL_EXISTS: 'EMAIL_ALREADY_EXISTS',
  // /accounts:sendOobCode for password reset when user is not found.
  EMAIL_NOT_FOUND: 'EMAIL_NOT_FOUND',
  // Reserved claim name.
  FORBIDDEN_CLAIM: 'FORBIDDEN_CLAIM',
  // Invalid claims provided.
  INVALID_CLAIMS: 'INVALID_CLAIMS',
  // Invalid session cookie duration.
  INVALID_DURATION: 'INVALID_SESSION_COOKIE_DURATION',
  // Invalid email provided.
  INVALID_EMAIL: 'INVALID_EMAIL',
  // Invalid new email provided.
  INVALID_NEW_EMAIL: 'INVALID_NEW_EMAIL',
  // Invalid tenant display name. This can be thrown on CreateTenant and UpdateTenant.
  INVALID_DISPLAY_NAME: 'INVALID_DISPLAY_NAME',
  // Invalid ID token provided.
  INVALID_ID_TOKEN: 'INVALID_ID_TOKEN',
  // Invalid tenant/parent resource name.
  INVALID_NAME: 'INVALID_NAME',
  // OIDC configuration has an invalid OAuth client ID.
  INVALID_OAUTH_CLIENT_ID: 'INVALID_OAUTH_CLIENT_ID',
  // Invalid page token.
  INVALID_PAGE_SELECTION: 'INVALID_PAGE_TOKEN',
  // Invalid phone number.
  INVALID_PHONE_NUMBER: 'INVALID_PHONE_NUMBER',
  // Invalid agent project. Either agent project doesn't exist or didn't enable multi-tenancy.
  INVALID_PROJECT_ID: 'INVALID_PROJECT_ID',
  // Invalid provider ID.
  INVALID_PROVIDER_ID: 'INVALID_PROVIDER_ID',
  // Invalid service account.
  INVALID_SERVICE_ACCOUNT: 'INVALID_SERVICE_ACCOUNT',
  // Invalid testing phone number.
  INVALID_TESTING_PHONE_NUMBER: 'INVALID_TESTING_PHONE_NUMBER',
  // Invalid tenant type.
  INVALID_TENANT_TYPE: 'INVALID_TENANT_TYPE',
  // Missing Android package name.
  MISSING_ANDROID_PACKAGE_NAME: 'MISSING_ANDROID_PACKAGE_NAME',
  // Missing configuration.
  MISSING_CONFIG: 'MISSING_CONFIG',
  // Missing configuration identifier.
  MISSING_CONFIG_ID: 'MISSING_PROVIDER_ID',
  // Missing tenant display name: This can be thrown on CreateTenant and UpdateTenant.
  MISSING_DISPLAY_NAME: 'MISSING_DISPLAY_NAME',
  // Email is required for the specified action. For example a multi-factor user requires
  // a verified email.
  MISSING_EMAIL: 'MISSING_EMAIL',
  // Missing iOS bundle ID.
  MISSING_IOS_BUNDLE_ID: 'MISSING_IOS_BUNDLE_ID',
  // Missing OIDC issuer.
  MISSING_ISSUER: 'MISSING_ISSUER',
  // No localId provided (deleteAccount missing localId).
  MISSING_LOCAL_ID: 'MISSING_UID',
  // OIDC configuration is missing an OAuth client ID.
  MISSING_OAUTH_CLIENT_ID: 'MISSING_OAUTH_CLIENT_ID',
  // Missing provider ID.
  MISSING_PROVIDER_ID: 'MISSING_PROVIDER_ID',
  // Missing SAML RP config.
  MISSING_SAML_RELYING_PARTY_CONFIG: 'MISSING_SAML_RELYING_PARTY_CONFIG',
  // Empty user list in uploadAccount.
  MISSING_USER_ACCOUNT: 'MISSING_UID',
  // Password auth disabled in console.
  OPERATION_NOT_ALLOWED: 'OPERATION_NOT_ALLOWED',
  // Provided credential has insufficient permissions.
  PERMISSION_DENIED: 'INSUFFICIENT_PERMISSION',
  // Phone number already exists.
  PHONE_NUMBER_EXISTS: 'PHONE_NUMBER_ALREADY_EXISTS',
  // Project not found.
  PROJECT_NOT_FOUND: 'PROJECT_NOT_FOUND',
  // In multi-tenancy context: project creation quota exceeded.
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED',
  // Currently only 5 second factors can be set on the same user.
  SECOND_FACTOR_LIMIT_EXCEEDED: 'SECOND_FACTOR_LIMIT_EXCEEDED',
  // Tenant not found.
  TENANT_NOT_FOUND: 'TENANT_NOT_FOUND',
  // Tenant ID mismatch.
  TENANT_ID_MISMATCH: 'MISMATCHING_TENANT_ID',
  // Token expired error.
  TOKEN_EXPIRED: 'ID_TOKEN_EXPIRED',
  // Continue URL provided in ActionCodeSettings has a domain that is not whitelisted.
  UNAUTHORIZED_DOMAIN: 'UNAUTHORIZED_DOMAIN',
  // A multi-factor user requires a supported first factor.
  UNSUPPORTED_FIRST_FACTOR: 'UNSUPPORTED_FIRST_FACTOR',
  // The request specified an unsupported type of second factor.
  UNSUPPORTED_SECOND_FACTOR: 'UNSUPPORTED_SECOND_FACTOR',
  // Operation is not supported in a multi-tenant context.
  UNSUPPORTED_TENANT_OPERATION: 'UNSUPPORTED_TENANT_OPERATION',
  // A verified email is required for the specified action. For example a multi-factor user
  // requires a verified email.
  UNVERIFIED_EMAIL: 'UNVERIFIED_EMAIL',
  // User on which action is to be performed is not found.
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  // User record is disabled.
  USER_DISABLED: 'USER_DISABLED',
  // Password provided is too weak.
  WEAK_PASSWORD: 'INVALID_PASSWORD',
  // Unrecognized reCAPTCHA action.
  INVALID_RECAPTCHA_ACTION: 'INVALID_RECAPTCHA_ACTION',
  // Unrecognized reCAPTCHA enforcement state.
  INVALID_RECAPTCHA_ENFORCEMENT_STATE: 'INVALID_RECAPTCHA_ENFORCEMENT_STATE',
  // reCAPTCHA is not enabled for account defender.
  RECAPTCHA_NOT_ENABLED: 'RECAPTCHA_NOT_ENABLED',
};
