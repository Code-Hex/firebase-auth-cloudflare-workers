import { encodeBase64Url } from "../src/base64";
import { KeyFetcher } from "../src/jwk-fetcher";
import { rs256alg } from "../src/jws-verifier";
import { DecodedHeader, DecodedPayload, JsonWebKeyWithKid } from "../src/jwt-decoder";
import { utf8Encoder } from "../src/utf8";

export class TestingKeyFetcher implements KeyFetcher {

  constructor(public readonly kid: string, private readonly keyPair: CryptoKeyPair) {}

  public static async withKeyPairGeneration(kid: string): Promise<TestingKeyFetcher> {
    const keyPair = await crypto.subtle.generateKey(rs256alg, true, ["sign", "verify"])
    return new TestingKeyFetcher(kid, keyPair)
  }

  public async fetchPublicKeys(): Promise<Array<JsonWebKeyWithKid>> {
    const publicJWK = await crypto.subtle.exportKey("jwk", this.keyPair.publicKey)
    return [{kid: this.kid, ...publicJWK}];
  }

  public getPrivateKey(): CryptoKey {
    return this.keyPair.privateKey
  }
}

export const genIat = (ms: number = Date.now()): number => Math.floor(ms / 1000)
export const genIss = (projectId: string = "projectId1234"): string => "https://securetoken.google.com/" + projectId

const jsonUTF8Stringify = (obj: any): Uint8Array => utf8Encoder.encode(JSON.stringify(obj))

export const signJWT = async (kid: string, payload: DecodedPayload, privateKey: CryptoKey) => {
  const header: DecodedHeader = {
    alg: 'RS256',
    typ: 'JWT',
    kid,
  };
  const encodedHeader = encodeBase64Url(jsonUTF8Stringify(header)).replace(/=/g, "")
  const encodedPayload = encodeBase64Url(jsonUTF8Stringify(payload)).replace(/=/g, "")
  const headerAndPayload = `${encodedHeader}.${encodedPayload}`;

  const signature = await crypto.subtle.sign(
    rs256alg,
    privateKey,
    utf8Encoder.encode(headerAndPayload),
  );

  const base64Signature = encodeBase64Url(signature).replace(/=/g, "")
  return `${headerAndPayload}.${base64Signature}`;
}
