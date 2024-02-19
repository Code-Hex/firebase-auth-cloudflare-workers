import crypto from 'node:crypto';
import { setGlobalDispatcher } from 'undici';
import { vi, beforeAll, afterAll } from 'vitest';
import { fetchMock } from './fetch';

vi.stubGlobal('crypto', crypto);

beforeAll(() => {
  setGlobalDispatcher(fetchMock);
});

afterAll(() => {
  fetchMock.deactivate();
  fetchMock.enableNetConnect();
});
