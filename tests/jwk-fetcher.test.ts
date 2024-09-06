import { Miniflare } from 'miniflare';
import { describe, it, expect, vi } from 'vitest';
import type { Fetcher } from '../src/jwk-fetcher';
import { isX509Certificates, parseMaxAge, UrlKeyFetcher } from '../src/jwk-fetcher';
import { WorkersKVStore } from '../src/key-store';

class HTTPMockFetcher implements Fetcher {
  constructor(private readonly response: Response) {}

  public fetch(): Promise<Response> {
    return Promise.resolve(this.response.clone());
  }
}

const nullScript = 'export default { fetch: () => new Response(null, { status: 404 }) };';
const mf = new Miniflare({
  modules: true,
  script: nullScript,
  kvNamespaces: ['TEST_NAMESPACE'],
});

const validResponseJSON = `
{
  "cc5e41843c5d52e68ef53e2bec98143da144905e": "-----BEGIN CERTIFICATE-----\\nMIIDHTCCAgWgAwIBAgIJAPQ9RP+nzEBDMA0GCSqGSIb3DQEBBQUAMDExLzAtBgNV\\nBAMMJnNlY3VyZXRva2VuLnN5c3RlbS5nc2VydmljZWFjY291bnQuY29tMB4XDTI0\\nMDgyODA3MzIzNloXDTI0MDkxMzE5NDczNlowMTEvMC0GA1UEAwwmc2VjdXJldG9r\\nZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqGSIb3DQEBAQUA\\nA4IBDwAwggEKAoIBAQC8aA7/f9gySpjIuASt2PS75x5L+GAcEddbdbi4PtNmE3LU\\n/tz6PNQ4TLNgSOT2wzmNby43qsGbcV/qJhhuZWrXwlBrZ7NzXbkBYrEU1VN9M9FU\\nv+G/NY4Nj56qRYxEG5q8bIxLFIkMARYG+e/B+vvP+RNPYySEyz6aedPWhdgG9hWd\\nTNYI6AR5rjpGwjaErsC/ImiGp8/Yk95LMh+mXk9Eg2mseo7qVkuPccsG/tGWD68S\\nJ4Maxc8/+UoAy7TQp7T77eNbYQCdXSMwpcWjx/8Ssc8R1XQ4f0IGzzZySC2v9Ntl\\njZRB00QjfCJw5TujvCmlY1B6yihRswKfNvbrRnp/AgMBAAGjODA2MAwGA1UdEwEB\\n/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMA0G\\nCSqGSIb3DQEBBQUAA4IBAQAAcoZJrUgyqYrBmCfLX8V6VwIyH/uW1CBTRnkZzXBU\\n5boTeYUHW/O8KS3Do6lE4WjRohTbHxdlyRfuYzzD7NTiTIinl7d913ge6tvAqLl7\\ng3sH1zXP8nUc9SGqYW37JTYf4/fdoNstnsx+f+FxUidxzXIAyrdq9iBpBtEGJBA2\\nr/oub4BGM7p+RLZgR0xcAwErJmRFQakc+iU6zUvtqnZ5fXqfIHA+31h2Ruoo67AL\\nZIPTjb/PlpPtxzHybYgLUfjYVxo4g+1NVRIxrELj3dTq++nciysMBKbsnbv7XmWg\\ncj6Em9ggGvXLjG5NAykt5szUeppBULiwocaV+cO/HR7J\\n-----END CERTIFICATE-----\\n",
  "02100716fdd904e5b4d49116ff5dbdfc98999401": "-----BEGIN CERTIFICATE-----\\nMIIDHDCCAgSgAwIBAgIIeUb2UFWyNWcwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\\nAwwmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjQw\\nOTA1MDczMjM3WhcNMjQwOTIxMTk0NzM3WjAxMS8wLQYDVQQDDCZzZWN1cmV0b2tl\\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\\nggEPADCCAQoCggEBALUgxhLcM8o5nE1znTeIJNt5wujFx7ZiX3QWMMpTD27ZR2lI\\n8yI2VTzBVq1uTpyyrsNqCros1HJL7tg1bThAXSMTqSSpjB4/PfWsnmEyULqoHVbw\\nB6xZfW8Oz7KBrDBWkj6pvOJt4zjlH844lF81eV7nkx0WRGeq412ksJyN3oYiGtJ8\\npmQLOW4dMPdrwEzGavVnarJA9HS4e/wOvzKoOpE3nqg/W4vwIwZWxQbNtsOH2mFP\\niA2f7xShEfEoNlaSIMhJ6wQz6u8SbdLxBvETnscHcg3HKXcCJ1sHXLQCS5oAnBpU\\nB53YPgUTPEaCVKGP0rYkT/06nXPoDdaEh5+kVhMCAwEAAaM4MDYwDAYDVR0TAQH/\\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\\nKoZIhvcNAQEFBQADggEBAFAS0bfPet+ykDU1BsqSCj7MplQhJoZTJ6FBbc5MhKmN\\n1Gei4Pu9Z8ogkfhOUezx//BvTUbVNldrXfCgBLpBl98qZ/Mjd8O2spw8ULuqIM72\\nGk/iukvUuAJBKHuNZx0qQ1S5W7jXW2VnDP4ZRASpCS63ZqyM+h/qkWx6VXggK/O1\\nvQWxvJC+nGTjJIX7uMg/mJ+Cd7ycIMXEPatQTt0ReI+9w47Je1p94iwx+xAsa7n3\\nYMsrN4EnQ9FeeLiSDhHVqfbBDKgPruHIKQsyFIM8h/CK8JGabV6j2wNc4zq3Tzle\\n+sYfDLo8aUudiJdY5ESLmM/9ckJ/gZ5ygsCwXGcFkME=\\n-----END CERTIFICATE-----\\n"
}
`;

const wantValidArray = [
  {
    kid: 'cc5e41843c5d52e68ef53e2bec98143da144905e',
    kty: 'RSA',
    n: 'vGgO_3_YMkqYyLgErdj0u-ceS_hgHBHXW3W4uD7TZhNy1P7c-jzUOEyzYEjk9sM5jW8uN6rBm3Ff6iYYbmVq18JQa2ezc125AWKxFNVTfTPRVL_hvzWODY-eqkWMRBuavGyMSxSJDAEWBvnvwfr7z_kTT2MkhMs-mnnT1oXYBvYVnUzWCOgEea46RsI2hK7AvyJohqfP2JPeSzIfpl5PRINprHqO6lZLj3HLBv7Rlg-vEieDGsXPP_lKAMu00Ke0--3jW2EAnV0jMKXFo8f_ErHPEdV0OH9CBs82ckgtr_TbZY2UQdNEI3wicOU7o7wppWNQesooUbMCnzb260Z6fw',
    e: 'AQAB',
  },
  {
    kid: '02100716fdd904e5b4d49116ff5dbdfc98999401',
    kty: 'RSA',
    n: 'tSDGEtwzyjmcTXOdN4gk23nC6MXHtmJfdBYwylMPbtlHaUjzIjZVPMFWrW5OnLKuw2oKuizUckvu2DVtOEBdIxOpJKmMHj899ayeYTJQuqgdVvAHrFl9bw7PsoGsMFaSPqm84m3jOOUfzjiUXzV5XueTHRZEZ6rjXaSwnI3ehiIa0nymZAs5bh0w92vATMZq9WdqskD0dLh7_A6_Mqg6kTeeqD9bi_AjBlbFBs22w4faYU-IDZ_vFKER8Sg2VpIgyEnrBDPq7xJt0vEG8ROexwdyDccpdwInWwdctAJLmgCcGlQHndg-BRM8RoJUoY_StiRP_Tqdc-gN1oSHn6RWEw',
    e: 'AQAB',
  },
];

describe('UrlKeyFetcher', () => {
  it('expected normal flow', async () => {
    const cacheKey = 'normal-flow-key';
    const mockedFetcher = new HTTPMockFetcher(
      new Response(validResponseJSON, {
        headers: {
          'Cache-Control': 'public, max-age=18793, must-revalidate, no-transform',
        },
      })
    );
    const TEST_NAMESPACE = await mf.getKVNamespace('TEST_NAMESPACE');
    const urlKeyFetcher = new UrlKeyFetcher(mockedFetcher, new WorkersKVStore(cacheKey, TEST_NAMESPACE));

    const httpFetcherSpy = vi.spyOn(mockedFetcher, 'fetch');

    // first call (no-cache in KV)
    const firstKeys = await urlKeyFetcher.fetchPublicKeys();
    expect(firstKeys).toEqual(wantValidArray);
    expect(httpFetcherSpy).toBeCalledTimes(1);

    // second call (has cache, get from KV)
    const secondKeys = await urlKeyFetcher.fetchPublicKeys();
    expect(secondKeys).toEqual(wantValidArray);
    expect(httpFetcherSpy).toBeCalledTimes(1); // same as first

    // cache is expired
    await TEST_NAMESPACE.delete(cacheKey);

    // third call (expired-cache, get from origin server)
    const thirdKeys = await urlKeyFetcher.fetchPublicKeys();
    expect(thirdKeys).toEqual(wantValidArray);
    expect(httpFetcherSpy).toBeCalledTimes(2); // updated
  });

  it('normal flow but not max-age header in response', async () => {
    const cacheKey = 'normal-non-max-age-flow-key';
    const mockedFetcher = new HTTPMockFetcher(
      new Response(validResponseJSON, {
        headers: {},
      })
    );
    const TEST_NAMESPACE = await mf.getKVNamespace('TEST_NAMESPACE');
    const urlKeyFetcher = new UrlKeyFetcher(mockedFetcher, new WorkersKVStore(cacheKey, TEST_NAMESPACE));

    const httpFetcherSpy = vi.spyOn(mockedFetcher, 'fetch');

    // first call (no-cache in KV)
    const firstKeys = await urlKeyFetcher.fetchPublicKeys();
    expect(firstKeys).toEqual(wantValidArray);
    expect(httpFetcherSpy).toBeCalledTimes(1);

    // second call (no cache, get from origin server)
    const secondKeys = await urlKeyFetcher.fetchPublicKeys();
    expect(secondKeys).toEqual(wantValidArray);
    expect(httpFetcherSpy).toBeCalledTimes(2);
  });

  it('internal server error fetch', async () => {
    const cacheKey = 'failed-fetch-flow-key';
    const internalServerMsg = 'Internal Server Error';
    const mockedFetcher = new HTTPMockFetcher(
      new Response(internalServerMsg, {
        status: 500,
      })
    );
    const TEST_NAMESPACE = await mf.getKVNamespace('TEST_NAMESPACE');
    const urlKeyFetcher = new UrlKeyFetcher(mockedFetcher, new WorkersKVStore(cacheKey, TEST_NAMESPACE));

    expect(() => urlKeyFetcher.fetchPublicKeys()).rejects.toThrowError(
      'Error fetching public keys for Google certs: ' + internalServerMsg
    );
  });

  // it('ok fetch but got text response', async () => {
  //   const cacheKey = 'ok-fetch-non-json-flow-key';
  //   const mockedFetcher = new HTTPMockFetcher(
  //     new Response('{}', {
  //       status: 200,
  //     })
  //   );
  //   const TEST_NAMESPACE = await mf.getKVNamespace('TEST_NAMESPACE');
  //   const urlKeyFetcher = new UrlKeyFetcher(mockedFetcher, new WorkersKVStore(cacheKey, TEST_NAMESPACE));

  //   expect(() => urlKeyFetcher.fetchPublicKeys()).rejects.toThrowError('The public keys are not an object or null:');
  // });
});

describe('parseMaxAge', () => {
  it.each([
    ['valid simple', 'max-age=604800', 604800],
    ['valid with other directives', 'public, max-age=18793, must-revalidate, no-transform', 18793],
    ['invalid cache-control header is null', null, NaN],
    ['invalid max-age is not found', 'public', NaN],
    ['invalid max-age is invalid format', 'public, max-age=hello', NaN],
  ])('%s', (_, cacheControlHeader, want) => {
    const maxAge = parseMaxAge(cacheControlHeader);
    expect(maxAge).toStrictEqual(want);
  });
});

describe('isX509Certificates', () => {
  it('should return true for valid isX509Certificates', () => {
    const valid = JSON.parse(validResponseJSON);
    expect(isX509Certificates(valid)).toBe(true);
  });

  it('should return false for null', () => {
    expect(isX509Certificates(null)).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isX509Certificates(undefined)).toBe(false);
  });

  it('should return false for non-object', () => {
    expect(isX509Certificates('string')).toBe(false);
    expect(isX509Certificates(123)).toBe(false);
    expect(isX509Certificates(true)).toBe(false);
  });

  it('should return false for object containing non-string values', () => {
    expect(isX509Certificates({ abc: 'a', xyz: 1 })).toBe(false);
    expect(isX509Certificates({ abc: 1, xyz: 'a' })).toBe(false);
    expect(isX509Certificates({ abc: true, xyz: 'a' })).toBe(false);
  });
});
