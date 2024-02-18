import { MockAgent } from 'undici';

// waiting to replace with:
// https://github.com/cloudflare/workers-sdk/tree/bcoll/vitest-pool-workers/packages/vitest-pool-workers
export const fetchMock = new MockAgent({ connections: 1 });
