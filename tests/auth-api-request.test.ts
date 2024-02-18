import type { MockInstance } from 'vitest';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { FIREBASE_AUTH_CREATE_SESSION_COOKIE } from '../src/auth-api-requests';
import * as validator from '../src/validator';

describe('FIREBASE_AUTH_CREATE_SESSION_COOKIE', () => {
  // Spy on all validators.
  let isNonEmptyString: MockInstance;
  let isNumber: MockInstance;

  beforeEach(() => {
    isNonEmptyString = vi.spyOn(validator, 'isNonEmptyString');
    isNumber = vi.spyOn(validator, 'isNumber');
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return the correct endpoint', () => {
    expect(FIREBASE_AUTH_CREATE_SESSION_COOKIE.getEndpoint()).to.equal(':createSessionCookie');
  });

  it('should return the correct http method', () => {
    expect(FIREBASE_AUTH_CREATE_SESSION_COOKIE.getHttpMethod()).to.equal('POST');
  });

  describe('requestValidator', () => {
    const requestValidator = FIREBASE_AUTH_CREATE_SESSION_COOKIE.getRequestValidator();
    it('should succeed with valid parameters passed', () => {
      const validRequest = { idToken: 'ID_TOKEN', validDuration: 60 * 60 };
      expect(() => {
        return requestValidator(validRequest);
      }).not.to.throw();
      expect(isNonEmptyString).toHaveBeenCalledWith('ID_TOKEN');
      expect(isNumber).toHaveBeenCalledWith(60 * 60);
    });
    it('should succeed with duration set at minimum allowed', () => {
      const validDuration = 60 * 5;
      const validRequest = { idToken: 'ID_TOKEN', validDuration };
      expect(() => {
        return requestValidator(validRequest);
      }).not.to.throw();
      expect(isNonEmptyString).toHaveBeenCalledWith('ID_TOKEN');
      expect(isNumber).toHaveBeenCalledWith(validDuration);
    });
    it('should succeed with duration set at maximum allowed', () => {
      const validDuration = 60 * 60 * 24 * 14;
      const validRequest = { idToken: 'ID_TOKEN', validDuration };
      expect(() => {
        return requestValidator(validRequest);
      }).not.to.throw();
      expect(isNonEmptyString).toHaveBeenCalledWith('ID_TOKEN');
      expect(isNumber).toHaveBeenCalledWith(validDuration);
    });
    it('should fail when idToken not passed', () => {
      const invalidRequest = { validDuration: 60 * 60 };
      expect(() => {
        return requestValidator(invalidRequest);
      }).to.throw();
      expect(isNonEmptyString).toHaveBeenCalledWith(undefined);
    });
    it('should fail when validDuration not passed', () => {
      const invalidRequest = { idToken: 'ID_TOKEN' };
      expect(() => {
        return requestValidator(invalidRequest);
      }).to.throw();
      expect(isNumber).toHaveBeenCalledWith(undefined);
    });
    describe('called with invalid parameters', () => {
      it('should fail with invalid idToken', () => {
        expect(() => {
          return requestValidator({ idToken: '', validDuration: 60 * 60 });
        }).to.throw();
        expect(isNonEmptyString).toHaveBeenCalledWith('');
      });
      it('should fail with invalid validDuration', () => {
        expect(() => {
          return requestValidator({ idToken: 'ID_TOKEN', validDuration: 'invalid' });
        }).to.throw();
        expect(isNonEmptyString).toHaveBeenCalledWith('ID_TOKEN');
        expect(isNumber).toHaveBeenCalledWith('invalid');
      });
      it('should fail with validDuration less than minimum allowed', () => {
        // Duration less 5 minutes.
        const outOfBoundDuration = 60 * 5 - 1;
        expect(() => {
          return requestValidator({ idToken: 'ID_TOKEN', validDuration: outOfBoundDuration });
        }).to.throw();
        expect(isNonEmptyString).toHaveBeenCalledWith('ID_TOKEN');
        expect(isNumber).toHaveBeenCalledWith(outOfBoundDuration);
      });
      it('should fail with validDuration greater than maximum allowed', () => {
        // Duration greater than 14 days.
        const outOfBoundDuration = 60 * 60 * 24 * 14 + 1;
        expect(() => {
          return requestValidator({ idToken: 'ID_TOKEN', validDuration: outOfBoundDuration });
        }).to.throw();
        expect(isNonEmptyString).toHaveBeenCalledWith('ID_TOKEN');
        expect(isNumber).toHaveBeenCalledWith(outOfBoundDuration);
      });
    });
  });
  describe('responseValidator', () => {
    const responseValidator = FIREBASE_AUTH_CREATE_SESSION_COOKIE.getResponseValidator();
    it('should succeed with sessionCookie returned', () => {
      const validResponse = { sessionCookie: 'SESSION_COOKIE' };
      expect(() => {
        return responseValidator(validResponse);
      }).not.to.throw();
    });
    it('should fail when no session cookie is returned', () => {
      const invalidResponse = {};
      expect(() => {
        responseValidator(invalidResponse);
      }).to.throw();
    });
  });
});
