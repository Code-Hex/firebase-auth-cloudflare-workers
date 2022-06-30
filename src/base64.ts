export const decodeBase64Url = (str: string): string => {
  return decodeBase64(str).replace(/_|-/g, (m) => ({ _: "/", "-": "+" }[m]!));;
};

export const decodeBase64UrlBytes = (str: string): Uint8Array =>
  new TextEncoder().encode(decodeBase64Url(str));

export const encodeBase64UrlBytes = (buf: ArrayBufferLike) => {
  return encodeBase64Url(String.fromCharCode(...new Uint8Array(buf)));
};

export const encodeBase64Url = (str: string): string =>
  encodeBase64(str).replace(/\/|\+/g, (m) => ({ "/": "_", "+": "-" }[m]!));

const pad = (s: string): string => {
  switch (s.length % 4) {
    case 2:
      return `${s}==`;
    case 3:
      return `${s}=`;
    default:
      return s;
  }
};

// This approach is written in MDN.
// btoa does not support utf-8 characters. So we need a little bit hack.
const encodeBase64 = (str: string): string => {
  const binary = []
  const encoded = new TextEncoder().encode(str)
  for (let i = 0; i < encoded.byteLength; i++) {
    binary.push(String.fromCharCode(encoded[i]))
  }
  return pad(btoa(binary.join('')))
}

// atob does not support utf-8 characters. So we need a little bit hack.
const decodeBase64 = (str: string): string => {
  const binary = atob(pad(str))
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes)
}