export const decodeBase64Url = (str: string): string => {
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
  pad(str).replace(/_|-/g, (m) => ({ _: "/", "-": "+" }[m]!));
  return atob(str);
};

export const decodeBase64UrlBytes = (str: string): Uint8Array =>
  new TextEncoder().encode(decodeBase64Url(str));

export const encodeBase64UrlBytes = (buf: ArrayBufferLike) => {
  return encodeBase64Url(String.fromCharCode(...new Uint8Array(buf)));
};

export const encodeBase64Url = (str: string): string =>
  btoa(str).replace(/\/|\+|=/g, (m) => ({ "/": "_", "+": "-", "=": "" }[m]!));
