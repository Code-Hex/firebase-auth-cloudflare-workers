/**
 * Validates that a string is a valid web URL.
 *
 * @param urlStr - The string to validate.
 * @returns Whether the string is valid web URL or not.
 */
export function isURL(urlStr: any): boolean {
  if (typeof urlStr !== 'string') {
    return false;
  }
  // Lookup illegal characters.
  const re = /[^a-z0-9:/?#[\]@!$&'()*+,;=.\-_~%]/i;
  if (re.test(urlStr)) {
    return false;
  }
  try {
    const uri = new URL(urlStr);
    const scheme = uri.protocol;
    const hostname = uri.hostname;
    const pathname = uri.pathname;
    if (scheme !== 'http:' && scheme !== 'https:') {
      return false;
    }
    // Validate hostname: Can contain letters, numbers, underscore and dashes separated by a dot.
    // Each zone must not start with a hyphen or underscore.
    if (!hostname || !/^[a-zA-Z0-9]+[\w-]*([.]?[a-zA-Z0-9]+[\w-]*)*$/.test(hostname)) {
      return false;
    }
    // Allow for pathnames: (/chars+)*/?
    // Where chars can be a combination of: a-z A-Z 0-9 - _ . ~ ! $ & ' ( ) * + , ; = : @ %
    const pathnameRe = /^(\/[\w\-.~!$'()*+,;=:@%]+)*\/?$/;
    // Validate pathname.
    if (pathname && pathname !== '/' && !pathnameRe.test(pathname)) {
      return false;
    }
    // Allow any query string and hash as long as no invalid character is used.
  } catch (e) {
    return false;
  }
  return true;
}

/**
 * Validates that a value is a number.
 *
 * @param value - The value to validate.
 * @returns Whether the value is a number or not.
 */
export function isNumber(value: any): value is number {
  return typeof value === 'number';
}

/**
 * Validates that a value is a string.
 *
 * @param value - The value to validate.
 * @returns Whether the value is a string or not.
 */
export function isString(value: any): value is string {
  return typeof value === 'string';
}

/**
 * Validates that a value is a non-empty string.
 *
 * @param value - The value to validate.
 * @returns Whether the value is a non-empty string or not.
 */
export function isNonEmptyString(value: any): value is string {
  return isString(value) && value !== '';
}

/**
 * Validates that a value is an array.
 *
 * @param value - The value to validate.
 * @returns Whether the value is an array or not.
 */
export function isArray<T>(value: any): value is T[] {
  return Array.isArray(value);
}

/**
   * 
/**
 * Validates that a value is a nullable object.
 *
 * @param value - The value to validate.
 * @returns Whether the value is an object or not.
 */
export function isObject(value: any): boolean {
  return typeof value === 'object' && !isArray(value);
}

/**
 * Validates that a value is a non-null object.
 *
 * @param value - The value to validate.
 * @returns Whether the value is a non-null object or not.
 */
export function isNonNullObject<T>(value: T | null | undefined): value is T {
  return isObject(value) && value !== null;
}
