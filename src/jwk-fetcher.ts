import crypto from 'node:crypto';
import type { JsonWebKeyWithKid } from './jwt-decoder';
import type { KeyStorer } from './key-store';
import { isNonNullObject, isURL } from './validator';

export interface KeyFetcher {
  fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>>;
}

export const isX509Certificates = (value: any): value is Record<string, string> => {
  if (!isNonNullObject(value)) {
    return false;
  }
  for (const v of Object.values(value)) {
    if (typeof v !== 'string') {
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

    async function x509ToJwk(pem: string, kid: string) {
      const cert = new crypto.X509Certificate(pem);
      const cryptoKey = await crypto.subtle.importKey(
        'spki',
        cert.publicKey.export({ type: 'spki', format: 'der' }),
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: 'SHA-256',
        },
        true,
        ['verify']
      );
      const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
      const jwkWithKid: JsonWebKeyWithKid = {
        kid,
        ...jwk,
      };
      return jwkWithKid;
    }

    const publicKeys = await resp.json();
    if (!isX509Certificates(publicKeys)) {
      throw new Error(`The public keys are not an object or null: "${publicKeys}`);
    }
    const jwks: JsonWebKeyWithKid[] = [];
    for (const [kid, pem] of Object.entries(publicKeys)) {
      jwks.push(await x509ToJwk(pem, kid));
    }

    const cacheControlHeader = resp.headers.get('cache-control');

    // store the public keys cache in the KV store.
    const maxAge = parseMaxAge(cacheControlHeader);
    if (!isNaN(maxAge) && maxAge > 0) {
      await this.keyStorer.put(JSON.stringify(jwks), maxAge);
    }

    return jwks;
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
