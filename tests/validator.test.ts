import { isArray, isNonEmptyString, isNonNullObject, isNumber, isObject, isString, isURL } from "../src/validator"

describe("validator", () => {
  describe("isURL", () => {
    test.each([
      ["http://example.com/", true],
      ["http://example.com", true],
      ["https://example.com/", true],
      ["https://example.com", true],
      ["https://www.example.com:8080", true],
      ["http://localhost/path/name/", true],
      ["https://www.example.com:8080/path/name/index.php?a=1&b=2&c=3#abcd", true],
      ["http://www.example.com:8080/path/name/index.php?a=1&b=2&c=3#abcd", true],
      ["http://localhost/path/name/index.php?a=1&b=2&c=3#abcd", true],
      ["http://127.0.0.1/path/name/index.php?a=1&b=2&c=3#abcd", true],
      ["http://a--b.c-c.co-uk/", true],
      [null, false],
      [undefined, false],
      [["https://example.com"], false], // non-null string
      ["ftp://www.example.com:8080/path/name/file.png", false],
      ["http://-abc.com", false],
      ["http://www._abc.com", false],
      ["http://.com", false],
      ["123456789", false]
    ])("%p", (param, want) => {
      expect(isURL(param)).toBe(want)
    })
  })

  describe("isNumber", () => {
    describe("non-number", () => {
      const nonNumbers = [undefined, null, true, false, '', 'a', [], ['a'], {}, { a: 1 }]
      nonNumbers.forEach((v) => {
        it(`${v}`, () => expect(isNumber(v)).toBeFalsy())
      })
    })

    describe("number", () => {
      const numbers = [NaN, 0, -1, 1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Infinity, -Infinity]
      numbers.forEach((v) => {
        it(`${v}`, () => expect(isNumber(v)).toBeTruthy())
      })
    })
  })

  describe("isString", () => {
    describe("non-string", () => {
      const nonStrings = [undefined, null, NaN, 0, 1, true, false, [], ['a'], {}, { a: 1 }]
      nonStrings.forEach((v) => {
        it(`${v}`, () => expect(isString(v)).toBeFalsy())
      })
    })

    describe("string", () => {
      const strings = [
        "",
        " ",
        "foo"
      ]
      strings.forEach((v) => {
        it(`${v}`, () => expect(isString(v)).toBeTruthy())
      })
    })
  })

  describe("isNonEmptyString", () => {
    describe("non-non-empty-string", () => {
      const nonStrings = [undefined, null, NaN, 0, 1, true, false, [], ['a'], {}, { a: 1 }, ""]
      nonStrings.forEach((v) => {
        it(`${v}`, () => expect(isNonEmptyString(v)).toBeFalsy())
      })
    })

    describe("non-empty-string", () => {
      const strings = [
        " ",
        "foo"
      ]
      strings.forEach((v) => {
        it(`${v}`, () => expect(isNonEmptyString(v)).toBeTruthy())
      })
    })
  })

  describe("isArray", () => {
    describe("non-array", () => {
      const nonArrays = [undefined, null, NaN, 0, 1, '', 'a', true, false, {}, { a: 1 }]
      nonArrays.forEach((v) => {
        it(`${v}`, () => expect(isArray(v)).toBeFalsy())
      })
    })

    describe("array", () => {
      const arrays = [
        [],
        [1,2,3],
        new Array(),
        new Array(1, 2, 3),
      ]
      arrays.forEach((v) => {
        it(`${v}`, () => expect(isArray(v)).toBeTruthy())
      })
    })
  })

  describe("isObject", () => {
    describe("non-object", () => {
      const nonObjects = [undefined, NaN, 0, 1, true, false, '', 'a', [], ['a']]
      nonObjects.forEach((v) => {
        it(`${v}`, () => expect(isObject(v)).toBeFalsy())
      })
    })

    describe("object", () => {
      const objects = [
        null,
        {},
        {a: 1}
      ]
      objects.forEach((v) => {
        it(`${v}`, () => expect(isObject(v)).toBeTruthy())
      })
    })
  })

  describe("isNonNullObject", () => {
    describe("non-non-null-object", () => {
      const nonNonNullObjects = [undefined, NaN, 0, 1, true, false, '', 'a', [], ['a'], null]
      nonNonNullObjects.forEach((v) => {
        it(`${v}`, () => expect(isNonNullObject(v)).toBeFalsy())
      })
    })

    describe("object", () => {
      const nonNullObjects = [
        {},
        {a: 1}
      ]
      nonNullObjects.forEach((v) => {
        it(`${v}`, () => expect(isNonNullObject(v)).toBeTruthy())
      })
    })
  })
})