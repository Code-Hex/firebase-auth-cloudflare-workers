import type { KeyStorer } from './key-store';
import { isNonNullObject, isObject, isURL } from './validator';
import { jwkFromX509 } from './x509';

export interface KeyFetcher {
  fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>>;
}

interface JWKMetadata {
  keys: Array<JsonWebKeyWithKid>;
}

export const isJWKMetadata = (value: any): value is JWKMetadata => {
  if (!isNonNullObject(value) || !value.keys) {
    return false;
  }
  const keys = value.keys;
  if (!Array.isArray(keys)) {
    return false;
  }
  const filtered = keys.filter(
    (key): key is JsonWebKeyWithKid => isObject(key) && !!key.kid && typeof key.kid === 'string'
  );
  return keys.length === filtered.length;
};

export const isX509Certificates = (value: any): value is Record<string, string> => {
  if (!isNonNullObject(value)) {
    return false;
  }
  const values = Object.values(value);
  if (values.length === 0) {
    return false;
  }
  for (const v of values) {
    if (typeof v !== 'string' || v === '') {
      return false;
    }
  }
  return true;
};

/**
 * Class to fetch public keys from a client certificates URL.
 */
export class UrlKeyFetcher implements KeyFetcher {
  constructor(
    private readonly fetcher: Fetcher,
    private readonly keyStorer: KeyStorer
  ) {}

  /**
   * Fetches the public keys for the Google certs.
   *
   * @returns A promise fulfilled with public keys for the Google certs.
   */
  public async fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>> {
    const publicKeys = await this.keyStorer.get<Array<JsonWebKeyWithKid>>();
    if (publicKeys === null || typeof publicKeys !== 'object') {
      return await this.refresh();
    }
    return publicKeys;
  }

  private async refresh(): Promise<Array<JsonWebKeyWithKid>> {
    const resp = await this.fetcher.fetch();
    if (!resp.ok) {
      const errorMessage = 'Error fetching public keys for Google certs: ';
      const text = await resp.text();
      throw new Error(errorMessage + text);
    }

    const json = await resp.json();
    const publicKeys = await this.retrievePublicKeys(json);

    const cacheControlHeader = resp.headers.get('cache-control');

    // store the public keys cache in the KV store.
    const maxAge = parseMaxAge(cacheControlHeader);
    if (!isNaN(maxAge) && maxAge > 0) {
      await this.keyStorer.put(JSON.stringify(publicKeys), maxAge);
    }

    return publicKeys;
  }

  private async retrievePublicKeys(json: unknown): Promise<Array<JsonWebKeyWithKid>> {
    if (isX509Certificates(json)) {
      const jwks: JsonWebKeyWithKid[] = [];
      for (const [kid, x509] of Object.entries(json)) {
        jwks.push(await jwkFromX509(kid, x509));
      }
      return jwks;
    }
    if (!isJWKMetadata(json)) {
      throw new Error(`The public keys are not an object or null: "${json}`);
    }
    return json.keys;
  }
}

// parseMaxAge parses Cache-Control header and returns max-age value as number.
// returns NaN when Cache-Control header is none or max-age is not found, the value is invalid.
export const parseMaxAge = (cacheControlHeader: string | null): number => {
  if (cacheControlHeader === null) {
    return NaN;
  }
  const parts = cacheControlHeader.split(',');
  for (const part of parts) {
    const subParts = part.trim().split('=');
    if (subParts[0] !== 'max-age') {
      continue;
    }
    return Number(subParts[1]); // maxAge is a seconds value.
  }
  return NaN;
};

export interface Fetcher {
  fetch(): Promise<Response>;
}

export class HTTPFetcher implements Fetcher {
  constructor(private readonly clientCertUrl: string) {
    if (!isURL(clientCertUrl)) {
      throw new Error('The provided public client certificate URL is not a valid URL.');
    }
  }

  public fetch(): Promise<Response> {
    return fetch(this.clientCertUrl);
  }
}
