import { decodeBase64UrlBytes } from "./base64";
import { JwtError, JwtErrorCode } from "./errors";
import { isNonEmptyString, isNumber, isString } from "./validator";

export interface TokenDecoder {
  decode(token: string): Promise<RS256Token>;
}

export interface JsonWebKeyWithKid extends JsonWebKey {
  kid: string;
}

type DecodedHeader = { kid: string; alg: "RS256" } & Record<string, any>;

export type DecodedPayload = {
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  sub: string;
} & Record<string, any>;

export type DecodedToken = {
  header: DecodedHeader;
  payload: DecodedPayload;
  signature: Uint8Array;
};

export class RS256Token {
  constructor(
    private rawToken: string,
    public readonly decodedToken: DecodedToken
  ) {}
  /**
   *
   * @param token - The JWT to verify.
   * @param currentTimestamp - Current timestamp in seconds since the Unix epoch.
   * @throw Error if the token is invalid.
   * @returns
   */
  public static decode(token: string, currentTimestamp: number): RS256Token {
    const tokenParts = token.split(".");
    if (tokenParts.length !== 3) {
      throw new JwtError(
        JwtErrorCode.INVALID_ARGUMENT,
        "token must consist of 3 parts"
      );
    }
    const header = decodeHeader(tokenParts[0]);
    const payload = decodePayload(tokenParts[1], currentTimestamp);

    return new RS256Token(token, {
      header,
      payload,
      signature: decodeBase64UrlBytes(tokenParts[2]),
    });
  }

  public getHeaderPayloadBytes(): Uint8Array {
    const rawToken = this.rawToken;

    // `${token.header}.${token.payload}`
    const trimmedSignature = rawToken.substring(0, rawToken.lastIndexOf("."));
    return new TextEncoder().encode(trimmedSignature);
  }
}

const decodeHeader = (headerPart: string): DecodedHeader => {
  const header = decodeBase64JSON(headerPart);
  const kid = header.kid;
  if (!isString(kid)) {
    throw new JwtError(
      JwtErrorCode.NO_KID_IN_HEADER,
      `kid must be a string but got ${kid}`
    );
  }
  const alg = header.alg;
  if (isString(alg) && alg !== "RS256") {
    throw new JwtError(
      JwtErrorCode.INVALID_ARGUMENT,
      `algorithm must be RS256 but got ${alg}`
    );
  }
  return header;
};

const decodePayload = (
  payloadPart: string,
  currentTimestamp: number
): DecodedPayload => {
  const payload = decodeBase64JSON(payloadPart);

  if (!isNonEmptyString(payload.aud)) {
    throw new JwtError(
      JwtErrorCode.INVALID_ARGUMENT,
      `"aud" claim must be a string but got ${payload.aud}}`
    );
  }

  if (!isNonEmptyString(payload.sub)) {
    throw new JwtError(
      JwtErrorCode.INVALID_ARGUMENT,
      `"sub" claim must be a string but got ${payload.sub}}`
    );
  }

  if (!isNonEmptyString(payload.iss)) {
    throw new JwtError(
      JwtErrorCode.INVALID_ARGUMENT,
      `"iss" claim must be a string but got ${payload.iss}}`
    );
  }

  if (!isNumber(payload.iat)) {
    throw new JwtError(
      JwtErrorCode.INVALID_ARGUMENT,
      `"iat" claim must be a number but got ${payload.iat}}`
    );
  }

  if (currentTimestamp < payload.iat) {
    throw new JwtError(
      JwtErrorCode.INVALID_ARGUMENT,
      `Incorrect "iat" claim must be a newer than "${currentTimestamp}" (iat: ${payload.iat})`
    );
  }

  if (!isNumber(payload.exp)) {
    throw new JwtError(
      JwtErrorCode.INVALID_ARGUMENT,
      `"exp" claim must be a number but got ${payload.exp}}`
    );
  }

  if (currentTimestamp >= payload.exp) {
    throw new JwtError(
      JwtErrorCode.TOKEN_EXPIRED,
      `Incorrect "exp" (expiration time) claim must be a older than "${currentTimestamp}" (exp: ${payload.exp})`
    );
  }

  return payload;
};

const decodeBase64JSON = (b64Url: string): any => {
  let b64 = b64Url.replace(/-/g, "+").replace(/_/g, "/");
  switch (b64.length % 4) {
    case 0:
      break;
    case 2:
      b64 += "==";
      break;
    case 3:
      b64 += "=";
      break;
    default:
      throw new Error("Illegal base64url string.");
  }
  try {
    return JSON.parse(decodeURIComponent(atob(b64)));
  } catch {
    return null;
  }
};
