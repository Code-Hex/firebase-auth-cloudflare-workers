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

// {
//   "keys": [
//     {
//       "kid": "f90fb1ae048a548fb681ad6092b0b869ea467ac6",
//       "e": "AQAB",
//       "kty": "RSA",
//       "n": "v1DLA89xpRpQ2bA2Ku__34z98eISnT1coBgA3QNjitmpM-4rf1pPNH6MKxOOj4ZxvzSeGlOjB7XiQwX3lQJ-ZDeSvS45fWIKrDW33AyFn-Z4VFJLVRb7j4sqLa6xsTj5rkbJBDwwGbGXOo37o5Ewfn0S52GFDjl2ALKexIgu7cUKKHsykr_h6D6RdhwpHvjG_H5Omq9mY7wDxLTvtYyrpN3wONAf4uMsJn9GDgMsAu7UkhDSICX5jmhVUDvYJA3FKokFyjG7PdetNnh00prL_CtH1Bs8f06sWwQKQMTDUrKEyEHuc2bzWNfGXRrc-c_gRNWP9k7vzOTcAIFSWlA7Fw",
//       "alg": "RS256",
//       "use": "sig"
//     },
//     {
//       "use": "sig",
//       "kid": "9897cf9459e254ff1c67a4eb6efea52f21a9ba14",
//       "n": "ylSiwcLD0KXrnzo4QlVFdVjx3OL5x0qYOgkcdLgiBxABUq9Y7AuIwABlCKVYcMCscUnooQvEATShnLdbqu0lLOaTiK1JxblIGonZrOB8-MlXn7-RnEmQNuMbvNK7QdwTrz3uzbqB64Z70DoC0qLVPT5v9ivzNfulh6UEuNVvFupC2zbrP84oxzRmpgcF0lxpiZf4qfCC2aKU8wDCqP14-PqHLI54nfm9QBLJLz4uS00OqdwWITSjX3nlBVcDqvCbJi3_V-eoBP42prVTreILWHw0SqP6FGt2lFPWeMnGinlRLAdwaEStrPzclvAupR5vEs3-m0UCOUt0rZOZBtTNkw",
//       "e": "AQAB",
//       "kty": "RSA",
//       "alg": "RS256"
//     }
//   ]
// }

/**
 * Class to fetch public keys from a client certificates URL.
 */
export class UrlKeyFetcher implements KeyFetcher {
  private readonly PUBLIC_KEY_CACHE_KEY = "google-public-jwks";

  constructor(
    private readonly clientCertUrl: string,
    private readonly cfKVNamespace: KVNamespace
  ) {
    if (!isURL(clientCertUrl)) {
      throw new Error(
        "The provided public client certificate URL is not a valid URL."
      );
    }
  }

  /**
   * Fetches the public keys for the Google certs.
   *
   * @returns A promise fulfilled with public keys for the Google certs.
   */
  public async fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>> {
    const publicKeys = await this.cfKVNamespace.get<Array<JsonWebKeyWithKid>>(
      this.PUBLIC_KEY_CACHE_KEY,
      "json"
    );
    if (publicKeys === null || typeof publicKeys !== "object") {
      return await this.refresh();
    }
    return publicKeys;
  }

  private async refresh(): Promise<Array<JsonWebKeyWithKid>> {
    // TODO(codehex): add retry
    const resp = await fetch(this.clientCertUrl);
    if (!resp.ok) {
      let errorMessage = "Error fetching public keys for Google certs: ";
      const text = await resp.text();
      throw new Error(errorMessage + text);
    }

    const publicKeys = await resp.json();
    if (!isJWKMetadata(publicKeys)) {
      throw new Error(
        `The public keys are not an object or null: '${publicKeys}'`
      );
    }

    const cacheControlHeader = resp.headers.get("cache-control");

    // store the public keys cache in the KV store.
    if (cacheControlHeader !== null) {
      const parts = cacheControlHeader.split(",");
      for (const part of parts) {
        const subParts = part.trim().split("=");
        if (subParts[0] !== "max-age") {
          continue;
        }
        const maxAge: number = +subParts[1]; // maxAge is a seconds value.
        this.cfKVNamespace.put(
          this.PUBLIC_KEY_CACHE_KEY,
          JSON.stringify(publicKeys.keys),
          {
            expirationTtl: maxAge,
          }
        );
      }
    }

    return publicKeys.keys;
  }
}

// This is an example of a response header that fetches public keys from a "clientCertUrl".
//   HTTP/2 200
//   < vary: X-Origin
//   < vary: Referer
//   < vary: Origin,Accept-Encoding
//   < server: scaffolding on HTTPServer2
//   < x-xss-protection: 0
//   < x-frame-options: SAMEORIGIN
//   < x-content-type-options: nosniff
//   < date: Sun, 26 Jun 2022 03:33:09 GMT
//   < expires: Sun, 26 Jun 2022 08:44:20 GMT
//   < cache-control: public, max-age=18671, must-revalidate, no-transform
//   < content-type: application/json; charset=UTF-8
//   < age: 32
//   < alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"
//   < accept-ranges: none
