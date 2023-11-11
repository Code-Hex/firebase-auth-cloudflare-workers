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
    (this as any).__proto__ = JwtError.prototype
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
  public static INVALID_CREDENTIAL = 'invalid-credential'
}

/**
 * Auth client error codes and their default messages.
 */
export class AuthClientErrorCode {
  public static INVALID_ARGUMENT = {
    code: 'argument-error',
    message: 'Invalid argument provided.',
  }
  public static INVALID_CREDENTIAL = {
    code: 'invalid-credential',
    message: 'Invalid credential object provided.',
  }
  public static ID_TOKEN_EXPIRED = {
    code: 'id-token-expired',
    message: 'The provided Firebase ID token is expired.',
  }
  public static ID_TOKEN_REVOKED = {
    code: 'id-token-revoked',
    message: 'The Firebase ID token has been revoked.',
  }
  public static INTERNAL_ERROR = {
    code: 'internal-error',
    message: 'An internal error has occurred.',
  }
  public static USER_NOT_FOUND = {
    code: 'user-not-found',
    message: 'There is no user record corresponding to the provided identifier.',
  }
  public static USER_DISABLED = {
    code: 'user-disabled',
    message: 'The user record is disabled.',
  }
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
    (this as any).__proto__ = FirebaseError.prototype
  }

  /** @returns The error code. */
  public get code(): string {
    return this.errorInfo.code
  }

  /** @returns The error message. */
  public get message(): string {
    return this.errorInfo.message
  }

  /** @returns The object representation of the error. */
  public toJSON(): object {
    return {
      code: this.code,
      message: this.message,
    }
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
    (this as any).__proto__ = PrefixedFirebaseError.prototype
  }

  /**
   * Allows the error type to be checked without needing to know implementation details
   * of the code prefixing.
   *
   * @param code - The non-prefixed error code to test against.
   * @returns True if the code matches, false otherwise.
   */
  public hasCode(code: string): boolean {
    return `${this.codePrefix}/${code}` === this.code
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
    (this as any).__proto__ = FirebaseAuthError.prototype
  }
}
