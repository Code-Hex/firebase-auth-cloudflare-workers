import { encodeObjectBase64Url } from './../tests/jwk-utils';
import { decodeBase64, encodeBase64Url } from './base64';
import { AppErrorCodes, FirebaseAppError } from './errors';
import { isNonEmptyString, isNonNullObject } from './validator';

/**
 * Type representing a Firebase OAuth access token (derived from a Google OAuth2 access token) which
 * can be used to authenticate to Firebase services such as the Realtime Database and Auth.
 */
export interface FirebaseAccessToken {
  accessToken: string;
  expirationTime: number;
}

/**
 * Interface for Google OAuth 2.0 access tokens.
 */
export interface GoogleOAuthAccessToken {
  access_token: string;
  expires_in: number;
}

/**
 * Interface that provides Google OAuth2 access tokens used to authenticate
 * with Firebase services.
 *
 * In most cases, you will not need to implement this yourself and can instead
 * use the default implementations provided by the `firebase-admin/app` module.
 */
export interface Credential {
  /**
   * Returns a Google OAuth2 access token object used to authenticate with
   * Firebase services.
   *
   * @returns A Google OAuth2 access token object.
   */
  getAccessToken(): Promise<GoogleOAuthAccessToken>;
}

const GOOGLE_TOKEN_AUDIENCE = 'https://accounts.google.com/o/oauth2/token';
const GOOGLE_AUTH_TOKEN_HOST = 'accounts.google.com';
const GOOGLE_AUTH_TOKEN_PATH = '/o/oauth2/token';

/**
 * Implementation of Credential that uses a service account.
 */
export class ServiceAccountCredential implements Credential {
  public readonly projectId: string;
  public readonly privateKey: string;
  public readonly clientEmail: string;

  /**
   * Creates a new ServiceAccountCredential from the given parameters.
   *
   * @param serviceAccountJson - Service account json content.
   *
   * @constructor
   */
  constructor(serviceAccountJson: string) {
    const serviceAccount = ServiceAccount.fromJSON(serviceAccountJson);
    this.projectId = serviceAccount.projectId;
    this.privateKey = serviceAccount.privateKey;
    this.clientEmail = serviceAccount.clientEmail;
  }

  public async getAccessToken(): Promise<GoogleOAuthAccessToken> {
    const header = encodeObjectBase64Url({
      alg: 'RS256',
      typ: 'JWT',
    }).replace(/=/g, '');

    const iat = Math.round(Date.now() / 1000);
    const exp = iat + 3600;
    const claim = encodeObjectBase64Url({
      iss: this.clientEmail,
      scope: ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/identitytoolkit'].join(
        ' '
      ),
      aud: GOOGLE_TOKEN_AUDIENCE,
      exp,
      iat,
    }).replace(/=/g, '');

    const unsignedContent = `${header}.${claim}`;
    // This method is actually synchronous so we can capture and return the buffer.
    const signature = await this.sign(unsignedContent, this.privateKey);
    const jwt = `${unsignedContent}.${signature}`;
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
    const url = `https://${GOOGLE_AUTH_TOKEN_HOST}${GOOGLE_AUTH_TOKEN_PATH}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cache-Control': 'no-cache',
        Host: 'oauth2.googleapis.com',
      },
      body,
    });
    const json = (await res.json()) as any;
    if (!json.access_token || !json.expires_in) {
      throw new FirebaseAppError(
        AppErrorCodes.INVALID_CREDENTIAL,
        `Unexpected response while fetching access token: ${JSON.stringify(json)}`
      );
    }

    return json;
  }

  private async sign(content: string, privateKey: string): Promise<string> {
    const buf = this.str2ab(content);
    const binaryKey = decodeBase64(privateKey);
    const signer = await crypto.subtle.importKey(
      'pkcs8',
      binaryKey,
      {
        name: 'RSASSA-PKCS1-V1_5',
        hash: { name: 'SHA-256' },
      },
      false,
      ['sign']
    );
    const binarySignature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-V1_5' }, signer, buf);
    return encodeBase64Url(binarySignature).replace(/=/g, '');
  }

  private str2ab(str: string): ArrayBuffer {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i += 1) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
}

/**
 * A struct containing the properties necessary to use service account JSON credentials.
 */
class ServiceAccount {
  public readonly projectId: string;
  public readonly privateKey: string;
  public readonly clientEmail: string;

  public static fromJSON(text: string): ServiceAccount {
    try {
      return new ServiceAccount(JSON.parse(text));
    } catch (error) {
      // Throw a nicely formed error message if the file contents cannot be parsed
      throw new FirebaseAppError(
        AppErrorCodes.INVALID_CREDENTIAL,
        'Failed to parse service account json file: ' + error
      );
    }
  }

  constructor(json: object) {
    if (!isNonNullObject(json)) {
      throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, 'Service account must be an object.');
    }

    copyAttr(this, json, 'projectId', 'project_id');
    copyAttr(this, json, 'privateKey', 'private_key');
    copyAttr(this, json, 'clientEmail', 'client_email');

    let errorMessage;
    if (!isNonEmptyString(this.projectId)) {
      errorMessage = 'Service account object must contain a string "project_id" property.';
    } else if (!isNonEmptyString(this.privateKey)) {
      errorMessage = 'Service account object must contain a string "private_key" property.';
    } else if (!isNonEmptyString(this.clientEmail)) {
      errorMessage = 'Service account object must contain a string "client_email" property.';
    }

    if (typeof errorMessage !== 'undefined') {
      throw new FirebaseAppError(AppErrorCodes.INVALID_CREDENTIAL, errorMessage);
    }

    this.privateKey = this.privateKey.replace(/-+(BEGIN|END).*/g, '').replace(/\s/g, '');
  }
}

/**
 * Copies the specified property from one object to another.
 *
 * If no property exists by the given "key", looks for a property identified by "alt", and copies it instead.
 * This can be used to implement behaviors such as "copy property myKey or my_key".
 *
 * @param to - Target object to copy the property into.
 * @param from - Source object to copy the property from.
 * @param key - Name of the property to copy.
 * @param alt - Alternative name of the property to copy.
 */
function copyAttr(to: { [key: string]: any }, from: { [key: string]: any }, key: string, alt: string): void {
  const tmp = from[key] || from[alt];
  if (typeof tmp !== 'undefined') {
    to[key] = tmp;
  }
}
