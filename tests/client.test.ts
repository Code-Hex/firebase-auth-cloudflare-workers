import { describe, it, expect, beforeAll } from 'vitest';
import { ApiSettings } from '../src/api-requests';
import { BaseClient, buildApiUrl } from '../src/client';
import type { EmulatorEnv } from '../src/emulator';
import { FirebaseAppError } from '../src/errors';
import { fetchMock } from './fetch';
import { NopCredential } from './firebase-utils';

describe('buildApiUrl', () => {
  it('should build correct url for production environment', () => {
    const projectId = 'test-project';
    const apiSettings = new ApiSettings('v1', '/test-endpoint');
    const expectedUrl = 'https://identitytoolkit.googleapis.com/v1/projects/test-project/test-endpoint';

    const result = buildApiUrl(projectId, apiSettings);

    expect(result).toBe(expectedUrl);
  });

  it('should build correct url for emulator environment', () => {
    const projectId = 'test-project';
    const apiSettings = new ApiSettings('v1', '/test-endpoint');
    const env: EmulatorEnv = { FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' };
    const expectedUrl = 'http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/projects/test-project/test-endpoint';

    const result = buildApiUrl(projectId, apiSettings, env);

    expect(result).toBe(expectedUrl);
  });
});

class TestClient extends BaseClient {
  async fetch<T>(apiSettings: ApiSettings, requestData?: object, env?: EmulatorEnv): Promise<T> {
    return await super.fetch(apiSettings, requestData, env);
  }
}

describe('BaseClient', () => {
  beforeAll(() => {
    fetchMock.disableNetConnect();
  });

  const projectid = 'test-project';
  const testUrl = `https://identitytoolkit.googleapis.com/v1/projects/${projectid}:test`;
  const u = new URL(testUrl);
  const apiSettings = new ApiSettings('v1', ':test', 'POST');

  it('should make valid request', async () => {
    const want = { data: 'test data' };

    const origin = fetchMock.get(u.origin);
    origin
      .intercept({
        method: 'POST',
        path: u.pathname,
      })
      .reply(200, JSON.stringify(want));

    const client = new TestClient(projectid, new NopCredential());
    const res = await client.fetch<{ data: string }>(apiSettings, {});

    expect(res).toEqual(want);
  });

  it('should retry on failure and eventually succeed', async () => {
    const want = { data: 'test data' };
    const errorResponse = { error: 'Server error' };

    const origin = fetchMock.get(u.origin);
    origin
      .intercept({
        method: 'POST',
        path: u.pathname,
      })
      .reply(503, JSON.stringify(errorResponse))
      .times(3);
    origin
      .intercept({
        method: 'POST',
        path: u.pathname,
      })
      .reply(200, JSON.stringify(want));

    const client = new TestClient(projectid, new NopCredential(), {
      maxRetries: 4,
      statusCodes: [503],
      maxDelayInMillis: 1000,
    });
    const res = await client.fetch<{ data: string }>(apiSettings, {});

    expect(res).toEqual(want);
  });

  it('should retry on failure but finally failure', async () => {
    const errorResponse = { error: 'Server error' };

    const origin = fetchMock.get(u.origin);
    origin
      .intercept({
        method: 'POST',
        path: u.pathname,
      })
      .reply(503, JSON.stringify(errorResponse))
      .times(5);

    const client = new TestClient(projectid, new NopCredential(), {
      maxRetries: 4,
      statusCodes: [503],
      maxDelayInMillis: 1000,
    });

    await expect(client.fetch<{ data: string }>(apiSettings, {})).rejects.toThrowError(FirebaseAppError);
  });
});
