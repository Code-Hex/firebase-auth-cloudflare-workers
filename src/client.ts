import type { ApiSettings } from './api-requests';
import type { Credential } from './credential';
import { useEmulator, type EmulatorEnv } from './emulator';
import { AppErrorCodes, FirebaseAppError } from './errors';
import { version } from './version';

/**
 * Specifies how failing HTTP requests should be retried.
 */
export interface RetryConfig {
  /** Maximum number of times to retry a given request. */
  maxRetries: number;

  /** HTTP status codes that should be retried. */
  statusCodes?: number[];

  /** Low-level I/O error codes that should be retried. */
  ioErrorCodes?: string[];

  /**
   * The multiplier for exponential back off. The retry delay is calculated in seconds using the formula
   * `(2^n) * backOffFactor`, where n is the number of retries performed so far. When the backOffFactor is set
   * to 0, retries are not delayed. When the backOffFactor is 1, retry duration is doubled each iteration.
   */
  backOffFactor?: number;

  /** Maximum duration to wait before initiating a retry. */
  maxDelayInMillis: number;
}

/**
 * Default retry configuration for HTTP requests. Retries up to 4 times on connection reset and timeout errors
 * as well as HTTP 503 errors. Exposed as a function to ensure that every HttpClient gets its own RetryConfig
 * instance.
 */
export function defaultRetryConfig(): RetryConfig {
  return {
    maxRetries: 4,
    statusCodes: [503],
    ioErrorCodes: ['ECONNRESET', 'ETIMEDOUT'],
    backOffFactor: 0.5,
    maxDelayInMillis: 60 * 1000,
  };
}

export function buildApiUrl(projectId: string, apiSettings: ApiSettings, env?: EmulatorEnv): string {
  const defaultAuthURL = 'https://identitytoolkit.googleapis.com';

  const baseUrl = env?.FIREBASE_AUTH_EMULATOR_HOST
    ? `http://${env.FIREBASE_AUTH_EMULATOR_HOST}/identitytoolkit.googleapis.com`
    : defaultAuthURL;
  const endpoint = apiSettings.getEndpoint();
  return `${baseUrl}/${apiSettings.getVersion()}/projects/${projectId}${endpoint}`;
}

export class BaseClient {
  constructor(
    private projectId: string,
    private credential: Credential,
    private retryConfig: RetryConfig = defaultRetryConfig()
  ) {}

  private async getToken(env?: EmulatorEnv): Promise<string> {
    if (useEmulator(env)) {
      return 'owner';
    }
    const result = await this.credential.getAccessToken();
    return result.access_token;
  }

  protected async fetch<T>(apiSettings: ApiSettings, requestData?: object, env?: EmulatorEnv): Promise<T> {
    const fullUrl = buildApiUrl(this.projectId, apiSettings, env);
    if (requestData) {
      const requestValidator = apiSettings.getRequestValidator();
      requestValidator(requestData);
    }
    const token = await this.getToken(env);
    const method = apiSettings.getHttpMethod();
    const signal = AbortSignal.timeout(25000); // 25s
    return await this.fetchWithRetry<T>(fullUrl, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'User-Agent': `Code-Hex/firebase-auth-cloudflare-workers/${version}`,
        'X-Client-Version': `Code-Hex/firebase-auth-cloudflare-workers/${version}`,
        'Content-Type': 'application/json;charset=utf-8',
      },
      body: requestData ? JSON.stringify(requestData) : undefined,
      signal,
    });
  }

  private async fetchWithRetry<T>(url: string, init: RequestInit, retryAttempts: number = 0): Promise<T> {
    try {
      const res = await fetch(url, init);
      const text = await res.text();
      if (!res.ok) {
        throw new HttpError(res.status, text);
      }
      try {
        return JSON.parse(text) as T;
      } catch (err) {
        throw new HttpError(res.status, text, {
          cause: new FirebaseAppError(
            AppErrorCodes.UNABLE_TO_PARSE_RESPONSE,
            `Error while parsing response data: "${String(err)}". Raw server ` +
              `response: "${text}". Status code: "${res.status}". Outgoing ` +
              `request: "${init.method} ${url}."`
          ),
        });
      }
    } catch (err) {
      const canRetry = this.isRetryEligible(retryAttempts, err);
      const delayMillis = this.backOffDelayMillis(retryAttempts);
      if (canRetry && delayMillis <= this.retryConfig.maxDelayInMillis) {
        await this.waitForRetry(delayMillis);
        return await this.fetchWithRetry(url, init, retryAttempts + 1);
      }
      if (err instanceof HttpError) {
        if (err.cause) {
          throw err.cause;
        }
        throw new FirebaseAppError(
          AppErrorCodes.INTERNAL_ERROR,
          `Error while sending request or reading response: "${err}". Raw server ` +
            `response: Status code: "${err.status}". Outgoing ` +
            `request: "${init.method} ${url}."`
        );
      }
      throw new FirebaseAppError(AppErrorCodes.NETWORK_ERROR, `Error while making request: ${String(err)}`);
    }
  }

  private waitForRetry(delayMillis: number): Promise<void> {
    if (delayMillis > 0) {
      return new Promise(resolve => {
        setTimeout(resolve, delayMillis);
      });
    }
    return Promise.resolve();
  }

  private isRetryEligible(retryAttempts: number, err: unknown): boolean {
    if (retryAttempts >= this.retryConfig.maxRetries) {
      return false;
    }
    if (err instanceof HttpError) {
      const statusCodes = this.retryConfig.statusCodes || [];
      return statusCodes.includes(err.status);
    }
    if (err instanceof Error && err.name === 'AbortError') {
      return false;
    }
    return true;
  }

  private backOffDelayMillis(retryAttempts: number): number {
    if (retryAttempts === 0) {
      return 0;
    }

    const backOffFactor = this.retryConfig.backOffFactor || 0;
    const delayInSeconds = 2 ** retryAttempts * backOffFactor;
    return Math.min(delayInSeconds * 1000, this.retryConfig.maxDelayInMillis);
  }
}

class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
    opts?: { cause?: unknown }
  ) {
    super(message, opts);
    this.name = 'HttpError';
  }
}
