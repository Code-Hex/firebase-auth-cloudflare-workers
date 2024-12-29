import { decodeBase64 } from './base64';

/**
 * Parses a sequence of ASN.1 elements from a given Uint8Array.
 * Internally, this function repeatedly calls `parseElement` on
 * the subarray until the entire sequence is consumed, returning
 * an array of parsed elements.
 */
function getElement(seq: Uint8Array) {
  const result = [];
  let next = 0;

  while (next < seq.length) {
    // Parse one ASN.1 element from the remaining subarray
    const nextPart = parseElement(seq.subarray(next));
    result.push(nextPart);
    // Advance the pointer by the element's total byte length
    next += nextPart.byteLength;
  }
  return result;
}

/**
 * Parses a single ASN.1 element (in DER encoding) from the given byte array.
 *
 * Each element consists of:
 *   1) Tag (possibly multiple bytes if 0x1f is encountered)
 *   2) Length (short form or long form, possibly indefinite)
 *   3) Contents (the data payload)
 *
 * Returns an object containing:
 *   - byteLength: total size (in bytes) of this element (including tag & length)
 *   - contents: Uint8Array of just the element's contents
 *   - raw: Uint8Array of the entire element (tag + length + contents)
 */
function parseElement(bytes: Uint8Array) {
  let position = 0;

  // --- Parse Tag ---
  // The tag is in the lower 5 bits (0x1f). If it's 0x1f, it indicates a multi-byte tag.
  let tag = bytes[0] & 0x1f;
  position++;
  if (tag === 0x1f) {
    tag = 0;
    // Continue reading the tag bytes while each byte >= 0x80
    while (bytes[position] >= 0x80) {
      tag = tag * 128 + bytes[position] - 0x80;
      position++;
    }
    tag = tag * 128 + bytes[position] - 0x80;
    position++;
  }

  // --- Parse Length ---
  let length = 0;
  // Short-form length: if less than 0x80, it's the length itself
  if (bytes[position] < 0x80) {
    length = bytes[position];
    position++;
  } else if (length === 0x80) {
    // Indefinite length form: scan until 0x00 0x00
    length = 0;
    while (bytes[position + length] !== 0 || bytes[position + length + 1] !== 0) {
      if (length > bytes.byteLength) {
        throw new TypeError('invalid indefinite form length');
      }
      length++;
    }
    const byteLength = position + length + 2;
    return {
      byteLength,
      contents: bytes.subarray(position, position + length),
      raw: bytes.subarray(0, byteLength),
    };
  } else {
    // Long-form length: the lower 7 bits of this byte indicates how many bytes follow for length
    const numberOfDigits = bytes[position] & 0x7f;
    position++;
    length = 0;
    // Accumulate the length from these "numberOfDigits" bytes
    for (let i = 0; i < numberOfDigits; i++) {
      length = length * 256 + bytes[position];
      position++;
    }
  }

  // The total byte length of this element (tag + length + contents)
  const byteLength = position + length;
  return {
    byteLength,
    contents: bytes.subarray(position, byteLength),
    raw: bytes.subarray(0, byteLength),
  };
}

/**
 * Extracts the SubjectPublicKeyInfo (SPKI) portion from a DER-encoded X.509 certificate.
 *
 * Steps:
 *   1) Parse the entire certificate as an ASN.1 SEQUENCE.
 *   2) Retrieve the TBS (To-Be-Signed) Certificate, which is the first element.
 *   3) Parse the TBS Certificate to get its internal fields (version, serial, issuer, etc.).
 *   4) Depending on whether the version field is present (tag = 0xa0), the SPKI is either
 *      at index 6 or 5 (skipping version if absent).
 *   5) Finally, encode the raw SPKI bytes in CryptoKey and return.
 */
async function spkiFromX509(buf: Uint8Array): Promise<CryptoKey> {
  // Parse the top-level ASN.1 structure, then get the top-level contents
  // which typically contain [ TBS Certificate, signatureAlgorithm, signature ].
  // Retrieve TBS Certificate as [0], then parse TBS Certificate further.
  const tbsCertificate = getElement(getElement(parseElement(buf).contents)[0].contents);

  // In the TBS Certificate, check whether the first element (index 0) is a version field (tag=0xa0).
  // If it is, the SubjectPublicKeyInfo is the 7th element (index 6).
  // Otherwise, it is the 6th element (index 5).
  const spki = tbsCertificate[tbsCertificate[0].raw[0] === 0xa0 ? 6 : 5].raw;
  return await crypto.subtle.importKey(
    'spki',
    spki,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    true,
    ['verify']
  );
}

export async function jwkFromX509(kid: string, x509: string): Promise<JsonWebKeyWithKid> {
  const pem = x509.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, '');
  const raw = decodeBase64(pem);
  const spki = await spkiFromX509(raw);
  const { kty, alg, n, e } = await crypto.subtle.exportKey('jwk', spki);
  return {
    kid,
    use: 'sig',
    kty,
    alg,
    n,
    e,
  };
}
