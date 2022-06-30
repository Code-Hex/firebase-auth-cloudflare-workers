import { JwtError, JwtErrorCode } from "./errors";
import { KeyFetcher, UrlKeyFetcher } from "./jwk-fetcher";
import { JsonWebKeyWithKid, RS256Token } from "./jwt-decoder";
import { isNonNullObject } from "./validator";

// https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
const rs256alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

export interface SignatureVerifier {
  verify(token: RS256Token): Promise<void>;
}

/**
 * Class for verifying JWT signature with a public key.
 */
export class PublicKeySignatureVerifier implements SignatureVerifier {
  constructor(private keyFetcher: KeyFetcher) {
    if (!isNonNullObject(keyFetcher)) {
      throw new Error("The provided key fetcher is not an object or null.");
    }
  }

  public static withCertificateUrl(
    clientCertUrl: string,
    cfKVNamespace: KVNamespace
  ): PublicKeySignatureVerifier {
    return new PublicKeySignatureVerifier(
      new UrlKeyFetcher(clientCertUrl, cfKVNamespace)
    );
  }

  /**
   * Verifies the signature of a JWT using the provided secret or a function to fetch
   * the public key.
   *
   * @param token - The JWT to be verified.
   * @throws If the JWT is not a valid RS256 token.
   * @returns A Promise resolving for a token with a valid signature.
   */
  public async verify(token: RS256Token): Promise<void> {
    const { header } = token.decodedToken;
    const publicKeys = await this.fetchPublicKeys();
    for (const publicKey of publicKeys) {
      if (publicKey.kid !== header.kid) {
        continue;
      }
      if (await this.verifySignature(token, publicKey)) {
        // succeeded
        return;
      }
      throw new JwtError(
        JwtErrorCode.INVALID_SIGNATURE,
        "The token signature is invalid."
      );
    }
    throw new JwtError(
      JwtErrorCode.NO_MATCHING_KID,
      "The token does not match the kid."
    );
  }

  private async verifySignature(
    token: RS256Token,
    publicJWK: JsonWebKeyWithKid
  ): Promise<boolean> {
    try {
      const key = await crypto.subtle.importKey(
        "jwk",
        publicJWK,
        rs256alg,
        false,
        ["verify"]
      );
      return await crypto.subtle.verify(
        rs256alg,
        key,
        token.decodedToken.signature,
        token.getHeaderPayloadBytes()
      );
    } catch (err) {
      throw new JwtError(
        JwtErrorCode.INVALID_SIGNATURE,
        `Error verifying signature: ${err}`
      );
    }
  }

  private async fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>> {
    try {
      return await this.keyFetcher.fetchPublicKeys();
    } catch (err) {
      throw new JwtError(
        JwtErrorCode.KEY_FETCH_ERROR,
        `Error fetching public keys for Google certs: ${err}`
      );
    }
  }
}
