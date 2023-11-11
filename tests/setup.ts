import crypto from 'node:crypto';
import { vi } from 'vitest';

vi.stubGlobal('crypto', crypto);
