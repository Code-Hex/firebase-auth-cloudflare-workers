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
    return await this.cfKVNamespace.get<ExpectedValue>(this.cacheKey, 'json')
  }

  public async put(value: string, expirationTtl: number): Promise<void> {
    await this.cfKVNamespace.put(this.cacheKey, value, {
      expirationTtl,
    })
  }
}
