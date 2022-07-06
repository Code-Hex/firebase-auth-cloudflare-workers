import { Fetcher, parseMaxAge, UrlKeyFetcher } from "../src/jwk-fetcher"
import { WorkersKVStore } from "../src/key-store";

class HTTPMockFetcher implements Fetcher {
  constructor(private readonly response: Response) { }

  public fetch(): Promise<Response> {
    return Promise.resolve(this.response.clone())
  }
}

const { TEST_NAMESPACE } = getMiniflareBindings();

const validResponseJSON = `{
  "keys": [
    {
      "kid": "f90fb1ae048a548fb681ad6092b0b869ea467ac6",
      "e": "AQAB",
      "kty": "RSA",
      "n": "v1DLA89xpRpQ2bA2Ku__34z98eISnT1coBgA3QNjitmpM-4rf1pPNH6MKxOOj4ZxvzSeGlOjB7XiQwX3lQJ-ZDeSvS45fWIKrDW33AyFn-Z4VFJLVRb7j4sqLa6xsTj5rkbJBDwwGbGXOo37o5Ewfn0S52GFDjl2ALKexIgu7cUKKHsykr_h6D6RdhwpHvjG_H5Omq9mY7wDxLTvtYyrpN3wONAf4uMsJn9GDgMsAu7UkhDSICX5jmhVUDvYJA3FKokFyjG7PdetNnh00prL_CtH1Bs8f06sWwQKQMTDUrKEyEHuc2bzWNfGXRrc-c_gRNWP9k7vzOTcAIFSWlA7Fw",
      "alg": "RS256",
      "use": "sig"
    },
    {
      "use": "sig",
      "kid": "9897cf9459e254ff1c67a4eb6efea52f21a9ba14",
      "n": "ylSiwcLD0KXrnzo4QlVFdVjx3OL5x0qYOgkcdLgiBxABUq9Y7AuIwABlCKVYcMCscUnooQvEATShnLdbqu0lLOaTiK1JxblIGonZrOB8-MlXn7-RnEmQNuMbvNK7QdwTrz3uzbqB64Z70DoC0qLVPT5v9ivzNfulh6UEuNVvFupC2zbrP84oxzRmpgcF0lxpiZf4qfCC2aKU8wDCqP14-PqHLI54nfm9QBLJLz4uS00OqdwWITSjX3nlBVcDqvCbJi3_V-eoBP42prVTreILWHw0SqP6FGt2lFPWeMnGinlRLAdwaEStrPzclvAupR5vEs3-m0UCOUt0rZOZBtTNkw",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256"
    }
  ]
}`

const wantValidArray = [
  {
    kid: "f90fb1ae048a548fb681ad6092b0b869ea467ac6",
    e: "AQAB",
    kty: "RSA",
    n: "v1DLA89xpRpQ2bA2Ku__34z98eISnT1coBgA3QNjitmpM-4rf1pPNH6MKxOOj4ZxvzSeGlOjB7XiQwX3lQJ-ZDeSvS45fWIKrDW33AyFn-Z4VFJLVRb7j4sqLa6xsTj5rkbJBDwwGbGXOo37o5Ewfn0S52GFDjl2ALKexIgu7cUKKHsykr_h6D6RdhwpHvjG_H5Omq9mY7wDxLTvtYyrpN3wONAf4uMsJn9GDgMsAu7UkhDSICX5jmhVUDvYJA3FKokFyjG7PdetNnh00prL_CtH1Bs8f06sWwQKQMTDUrKEyEHuc2bzWNfGXRrc-c_gRNWP9k7vzOTcAIFSWlA7Fw",
    alg: "RS256",
    use: "sig"
  },
  {
    use: "sig",
    kid: "9897cf9459e254ff1c67a4eb6efea52f21a9ba14",
    n: "ylSiwcLD0KXrnzo4QlVFdVjx3OL5x0qYOgkcdLgiBxABUq9Y7AuIwABlCKVYcMCscUnooQvEATShnLdbqu0lLOaTiK1JxblIGonZrOB8-MlXn7-RnEmQNuMbvNK7QdwTrz3uzbqB64Z70DoC0qLVPT5v9ivzNfulh6UEuNVvFupC2zbrP84oxzRmpgcF0lxpiZf4qfCC2aKU8wDCqP14-PqHLI54nfm9QBLJLz4uS00OqdwWITSjX3nlBVcDqvCbJi3_V-eoBP42prVTreILWHw0SqP6FGt2lFPWeMnGinlRLAdwaEStrPzclvAupR5vEs3-m0UCOUt0rZOZBtTNkw",
    e: "AQAB",
    kty: "RSA",
    alg: "RS256"
  }
]

describe("UrlKeyFetcher", () => {
  it("expected normal flow", async () => {
    const cacheKey = "normal-flow-key"
    const mockedFetcher = new HTTPMockFetcher(
      new Response(validResponseJSON, {
        headers: {
          "Cache-Control": "public, max-age=18793, must-revalidate, no-transform"
        }
      }),
    )
    const urlKeyFetcher = new UrlKeyFetcher(
      mockedFetcher,
      new WorkersKVStore(cacheKey, TEST_NAMESPACE),
    )

    const httpFetcherSpy = jest.spyOn(mockedFetcher, "fetch")

    // first call (no-cache in KV)
    const firstKeys = await urlKeyFetcher.fetchPublicKeys()
    expect(firstKeys).toEqual(wantValidArray)
    expect(httpFetcherSpy).toBeCalledTimes(1)

    // second call (has cache, get from KV)
    const secondKeys = await urlKeyFetcher.fetchPublicKeys()
    expect(secondKeys).toEqual(wantValidArray)
    expect(httpFetcherSpy).toBeCalledTimes(1) // same as first

    // cache is expired
    await TEST_NAMESPACE.delete(cacheKey)

    // third call (expired-cache, get from origin server)
    const thirdKeys = await urlKeyFetcher.fetchPublicKeys()
    expect(thirdKeys).toEqual(wantValidArray)
    expect(httpFetcherSpy).toBeCalledTimes(2) // updated
  })

  it("normal flow but not max-age header in response", async () => {
    const cacheKey = "normal-non-max-age-flow-key"
    const mockedFetcher = new HTTPMockFetcher(
      new Response(validResponseJSON, {
        headers: {}
      }),
    )
    const urlKeyFetcher = new UrlKeyFetcher(
      mockedFetcher,
      new WorkersKVStore(cacheKey, TEST_NAMESPACE),
    )

    const httpFetcherSpy = jest.spyOn(mockedFetcher, "fetch")

    // first call (no-cache in KV)
    const firstKeys = await urlKeyFetcher.fetchPublicKeys()
    expect(firstKeys).toEqual(wantValidArray)
    expect(httpFetcherSpy).toBeCalledTimes(1)

    // second call (no cache, get from origin server)
    const secondKeys = await urlKeyFetcher.fetchPublicKeys()
    expect(secondKeys).toEqual(wantValidArray)
    expect(httpFetcherSpy).toBeCalledTimes(2)
  })

  it("internal server error fetch", () => {
    const cacheKey = "failed-fetch-flow-key"
    const internalServerMsg = "Internal Server Error"
    const mockedFetcher = new HTTPMockFetcher(
      new Response(internalServerMsg, {
        status: 500
      }),
    )
    const urlKeyFetcher = new UrlKeyFetcher(
      mockedFetcher,
      new WorkersKVStore(cacheKey, TEST_NAMESPACE),
    )

    expect(() => urlKeyFetcher.fetchPublicKeys()).rejects.toThrowError(
      "Error fetching public keys for Google certs: " + internalServerMsg
    )
  })

  it("ok fetch but got text response", () => {
    const cacheKey = "ok-fetch-non-json-flow-key"
    const mockedFetcher = new HTTPMockFetcher(
      new Response("{}", {
        status: 200
      }),
    )
    const urlKeyFetcher = new UrlKeyFetcher(
      mockedFetcher,
      new WorkersKVStore(cacheKey, TEST_NAMESPACE),
    )

    expect(() => urlKeyFetcher.fetchPublicKeys()).rejects.toThrowError(
      "The public keys are not an object or null:"
    )
  })
})

describe("parseMaxAge", () => {
  test.each([
    [
      "valid simple",
      "max-age=604800",
      604800,
    ],
    [
      "valid with other directives",
      "public, max-age=18793, must-revalidate, no-transform",
      18793,
    ],
    [
      "invalid cache-control header is null",
      null,
      NaN,
    ],
    [
      "invalid max-age is not found",
      "public",
      NaN,
    ],
    [
      "invalid max-age is invalid format",
      "public, max-age=hello",
      NaN,
    ]
  ])("%s", (_, cacheControlHeader, want) => {
    const maxAge = parseMaxAge(cacheControlHeader)
    expect(maxAge).toStrictEqual(want)
  })
})