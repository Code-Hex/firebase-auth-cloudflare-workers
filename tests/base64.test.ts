import { describe, it, expect } from 'vitest';
import { decodeBase64Url, encodeBase64Url } from '../src/base64';
import { utf8Encoder } from '../src/utf8';

const urlRef = (s: string): string => s.replace(/\+|\//g, m => ({ '+': '-', '/': '_' }[m] ?? m));

const str2UInt8Array = (s: string): Uint8Array => {
  const buffer = new Uint8Array(new ArrayBuffer(s.length));
  for (let i = 0; i < buffer.byteLength; i++) {
    buffer[i] = s.charCodeAt(i);
  }
  return buffer;
};

describe('base64', () => {
  describe.each([
    // basic
    [utf8Encoder.encode('Hello, 世界'), 'SGVsbG8sIOS4lueVjA=='],

    // RFC 3548 examples
    [str2UInt8Array('\x14\xfb\x9c\x03\xd9\x7e'), 'FPucA9l+'],
    [str2UInt8Array('\x14\xfb\x9c\x03\xd9'), 'FPucA9k='],
    [str2UInt8Array('\x14\xfb\x9c\x03'), 'FPucAw=='],

    // RFC 4648 examples
    [str2UInt8Array(''), ''],
    [str2UInt8Array('f'), 'Zg=='],
    [str2UInt8Array('fo'), 'Zm8='],
    [str2UInt8Array('foo'), 'Zm9v'],
    [str2UInt8Array('foob'), 'Zm9vYg=='],
    [str2UInt8Array('fooba'), 'Zm9vYmE='],
    [str2UInt8Array('foobar'), 'Zm9vYmFy'],

    // Wikipedia examples
    [str2UInt8Array('sure.'), 'c3VyZS4='],
    [str2UInt8Array('sure'), 'c3VyZQ=='],
    [str2UInt8Array('sur'), 'c3Vy'],
    [str2UInt8Array('su'), 'c3U='],
    [str2UInt8Array('leasure.'), 'bGVhc3VyZS4='],
    [str2UInt8Array('easure.'), 'ZWFzdXJlLg=='],
    [str2UInt8Array('asure.'), 'YXN1cmUu'],
    [str2UInt8Array('sure.'), 'c3VyZS4='],
  ])('%s, %s', (decoded, encoded) => {
    it('encode', () => {
      const got = encodeBase64Url(decoded);
      const want = urlRef(encoded);
      expect(got).toStrictEqual(want);
    });
    it('decode', () => {
      const got = decodeBase64Url(urlRef(encoded));
      const want = decoded;
      expect(got).toStrictEqual(want);
    });
  });
});
