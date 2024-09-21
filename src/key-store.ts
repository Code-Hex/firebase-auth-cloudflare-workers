export interface KeyStorer {
  get<ExpectedValue = unknown>(): Promise<ExpectedValue | null>;
  put(value: string, expirationTtl: number): Promise<void>;
}

/**
 * Class to get or store fetched public keys from a client certificates URL.
 */
export class WorkersKVStore implements KeyStorer {
  constructor(
    private readonly cacheKey: string,
    private readonly cfKVNamespace: KVNamespace
  ) {}

  public async get<ExpectedValue = unknown>(): Promise<ExpectedValue | null> {
    return await this.cfKVNamespace.get<ExpectedValue>(this.cacheKey, 'json');
  }

  public async put(value: string, expirationTtl: number): Promise<void> {
    await this.cfKVNamespace.put(this.cacheKey, value, {
      expirationTtl,
    });
  }
}

export class InMemoryStore implements KeyStorer {
  private val: string | null = null;
  private expireAt: number = 0;

  async get() {
    if (Date.now() > this.expireAt) {
      this.val = null;
    }
    return this.val ? JSON.parse(this.val) : null;
  }
  async put(value: string, expirationTtl: number) {
    this.expireAt = Date.now() + expirationTtl * 1000;
    this.val = value;
  }
}
