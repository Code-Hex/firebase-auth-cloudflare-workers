import { decodeBase64Url, encodeBase64Url } from "./base64";

const urlRef = (s: string): string =>
  s.replace(/\+|\//g, (m) => ({ "+": "-", "/": "_" }[m]!))

describe("base64", () => {
  describe.each([
    // basic
    ["Hello, 世界", "SGVsbG8sIOS4lueVjA=="],

    // RFC 3548 examples (TODO(codehex): clear)
    // ["\x14\xfb\x9c\x03\xd9\x7e", "FPucA9l+"],
    // ["\x14\xfb\x9c\x03\xd9", "FPucA9k="],
    // ["\x14\xfb\x9c\x03", "FPucAw=="],

    // RFC 4648 examples
    ["", ""],
    ["f", "Zg=="],
    ["fo", "Zm8="],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg=="],
    ["fooba", "Zm9vYmE="],
    ["foobar", "Zm9vYmFy"],

    // Wikipedia examples
    ["sure.", "c3VyZS4="],
    ["sure", "c3VyZQ=="],
    ["sur", "c3Vy"],
    ["su", "c3U="],
    ["leasure.", "bGVhc3VyZS4="],
    ["easure.", "ZWFzdXJlLg=="],
    ["asure.", "YXN1cmUu"],
    ["sure.", "c3VyZS4="],
  ])('%s, %s', (decoded, encoded) => {
    it("encode", () => {
      const got = encodeBase64Url(decoded)
      const want = urlRef(encoded)
      expect(got).toBe(want)
    })
    it("decode", () => {
      const got = decodeBase64Url(urlRef(encoded))
      const want = decoded
      expect(got).toBe(want)
    })
  })
})