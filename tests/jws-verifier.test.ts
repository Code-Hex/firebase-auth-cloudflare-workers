import { JwtError, JwtErrorCode } from "../src/errors"
import { PublicKeySignatureVerifier, rs256alg } from "../src/jws-verifier"
import { DecodedPayload, RS256Token } from "../src/jwt-decoder"
import { genTime, genIss, signJWT, TestingKeyFetcher } from "./jwk-utils"

describe("PublicKeySignatureVerifier", () => {
  const kid = "kid123456"
  const projectId = "projectId1234"
  const currentTimestamp = genTime(Date.now())
  const payload: DecodedPayload = {
    aud: projectId,
    exp: currentTimestamp + 9999,
    iat: currentTimestamp - 10000, // -10s
    iss: genIss(projectId),
    sub: "userId12345",
  }

  it("valid", async () => {
    const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration(kid)
    const verifier = new PublicKeySignatureVerifier(testingKeyFetcher)

    const jwt = await signJWT(kid, payload, testingKeyFetcher.getPrivateKey())
    const rs256Token = RS256Token.decode(jwt, currentTimestamp)
    await verifier.verify(rs256Token)
  })

  it("invalid public key", async () => {
    const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration(kid)
    const verifier = new PublicKeySignatureVerifier(testingKeyFetcher)
    const anotherKeyPair = await crypto.subtle.generateKey(rs256alg, true, ["sign", "verify"])

    // set another private key
    const jwt = await signJWT(kid, payload, anotherKeyPair.privateKey)
    const rs256Token = RS256Token.decode(jwt, currentTimestamp)
    await expect(verifier.verify(rs256Token)).rejects.toThrowError(
      new JwtError(
        JwtErrorCode.INVALID_SIGNATURE,
        "The token signature is invalid."
      ))
  })

  it("invalid kid", async () => {
    const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration("mismachKid")
    const verifier = new PublicKeySignatureVerifier(testingKeyFetcher)
    const jwt = await signJWT(kid, payload, testingKeyFetcher.getPrivateKey())
    const rs256Token = RS256Token.decode(jwt, currentTimestamp)
    await expect(verifier.verify(rs256Token)).rejects.toThrowError(
      new JwtError(
        JwtErrorCode.NO_MATCHING_KID,
      "The token does not match the kid."
      ))
  })
})
