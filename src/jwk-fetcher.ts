import { JsonWebKeyWithKid } from "./jwt-decoder";
import { isArray, isNonNullObject, isURL } from "./validator";

export interface KeyFetcher {
  fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>>;
}

interface JWKMetadata {
  keys: Array<JsonWebKeyWithKid>;
}

const isJWKMetadata = (value: any): value is JWKMetadata =>
  isNonNullObject(value) && !!value.keys && isArray(value.keys);

/**
 * Class to fetch public keys from a client certificates URL.
 */
export class UrlKeyFetcher implements KeyFetcher {
  constructor(
    private readonly fetcher: Fetcher,
    private readonly cacheKey: string,
    private readonly cfKVNamespace: KVNamespace
  ) {}

  /**
   * Fetches the public keys for the Google certs.
   *
   * @returns A promise fulfilled with public keys for the Google certs.
   */
  public async fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>> {
    const publicKeys = await this.cfKVNamespace.get<Array<JsonWebKeyWithKid>>(
      this.cacheKey,
      "json"
    );
    if (publicKeys === null || typeof publicKeys !== "object") {
      return await this.refresh();
    }
    return publicKeys;
  }

  private async refresh(): Promise<Array<JsonWebKeyWithKid>> {
    const resp = await this.fetcher.fetch();
    if (!resp.ok) {
      let errorMessage = "Error fetching public keys for Google certs: ";
      const text = await resp.text();
      throw new Error(errorMessage + text);
    }

    const publicKeys = await resp.json();
    if (!isJWKMetadata(publicKeys)) {
      throw new Error(
        `The public keys are not an object or null: "${publicKeys}`
      );
    }

    const cacheControlHeader = resp.headers.get("cache-control");

    // store the public keys cache in the KV store.
    const maxAge = parseMaxAge(cacheControlHeader)
    if (!isNaN(maxAge)) {
      this.cfKVNamespace.put(
        this.cacheKey,
        JSON.stringify(publicKeys.keys),
        {
          expirationTtl: maxAge,
        }
      );
    }

    return publicKeys.keys;
  }
}

// parseMaxAge parses Cache-Control header and returns max-age value as number.
// returns NaN when Cache-Control header is none or max-age is not found, the value is invalid.
export const parseMaxAge = (cacheControlHeader: string | null): number => {
  if (cacheControlHeader === null) {
    return NaN
  }
  const parts = cacheControlHeader.split(",");
  for (const part of parts) {
    const subParts = part.trim().split("=");
    if (subParts[0] !== "max-age") {
      continue;
    }
    return Number(subParts[1]); // maxAge is a seconds value.
  }
  return NaN
}

export interface Fetcher {
  fetch(): Promise<Response>
}

export class HTTPFetcher implements Fetcher {
  constructor(
    private readonly clientCertUrl: string,
  ) {
    if (!isURL(clientCertUrl)) {
      throw new Error(
        "The provided public client certificate URL is not a valid URL."
      );
    }
  }

  public fetch(): Promise<Response> {
    return fetch(this.clientCertUrl)
  }
}