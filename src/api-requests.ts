/** Http method type definition. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD';
/** API callback function type definition. */
export type ApiCallbackFunction = (data: object) => void;

/**
 * Class that defines all the settings for the backend API endpoint.
 *
 * @param endpoint - The Firebase Auth backend endpoint.
 * @param httpMethod - The http method for that endpoint.
 * @constructor
 */
export class ApiSettings {
  private requestValidator: ApiCallbackFunction;
  private responseValidator: ApiCallbackFunction;

  constructor(
    private version: 'v1' | 'v2',
    private endpoint: string,
    private httpMethod: HttpMethod = 'POST'
  ) {
    this.setRequestValidator(null).setResponseValidator(null);
  }

  /** @returns The backend API resource version. */
  public getVersion(): 'v1' | 'v2' {
    return this.version;
  }

  /** @returns The backend API endpoint. */
  public getEndpoint(): string {
    return this.endpoint;
  }

  /** @returns The request HTTP method. */
  public getHttpMethod(): HttpMethod {
    return this.httpMethod;
  }

  /**
   * @param requestValidator - The request validator.
   * @returns The current API settings instance.
   */
  public setRequestValidator(requestValidator: ApiCallbackFunction | null): ApiSettings {
    const nullFunction: ApiCallbackFunction = () => undefined;
    this.requestValidator = requestValidator || nullFunction;
    return this;
  }

  /** @returns The request validator. */
  public getRequestValidator(): ApiCallbackFunction {
    return this.requestValidator;
  }

  /**
   * @param responseValidator - The response validator.
   * @returns The current API settings instance.
   */
  public setResponseValidator(responseValidator: ApiCallbackFunction | null): ApiSettings {
    const nullFunction: ApiCallbackFunction = () => undefined;
    this.responseValidator = responseValidator || nullFunction;
    return this;
  }

  /** @returns The response validator. */
  public getResponseValidator(): ApiCallbackFunction {
    return this.responseValidator;
  }
}
