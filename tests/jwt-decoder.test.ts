import { describe, it, expect } from 'vitest'
import { JwtError, JwtErrorCode } from '../src/errors'
import type { DecodedHeader, DecodedPayload } from '../src/jwt-decoder'
import { RS256Token } from '../src/jwt-decoder'
import { genTime, genIss, signJWT, TestingKeyFetcher, encodeObjectBase64Url } from './jwk-utils'

describe('TokenDecoder', () => {
  const kid = 'kid123456'
  const projectId = 'projectId1234'
  const currentTimestamp = genTime(Date.now())
  const payload: DecodedPayload = {
    aud: projectId,
    exp: currentTimestamp, // now (for border test)
    iat: currentTimestamp - 10000, // -10s
    iss: genIss(projectId),
    sub: 'userId12345',
  }

  it('invalid token', () => {
    expect(() => RS256Token.decode('invalid', currentTimestamp)).toThrowError(
      new JwtError(JwtErrorCode.INVALID_ARGUMENT, 'token must consist of 3 parts')
    )
  })

  describe('header', () => {
    const validHeader: DecodedHeader = {
      kid,
      alg: 'RS256',
    }

    it('invalid kid', () => {
      const headerPart = encodeObjectBase64Url({
        ...validHeader,
        kid: undefined,
      })
      const jwt = `${headerPart}.payload.signature`
      expect(() => RS256Token.decode(jwt, currentTimestamp)).toThrowError(
        new JwtError(JwtErrorCode.NO_KID_IN_HEADER, `kid must be a string but got ${undefined}`)
      )
    })

    it('invalid alg', () => {
      const headerPart = encodeObjectBase64Url({
        ...validHeader,
        alg: 'HS256',
      })
      const jwt = `${headerPart}.payload.signature`
      expect(() => RS256Token.decode(jwt, currentTimestamp)).toThrowError(
        new JwtError(JwtErrorCode.INVALID_ARGUMENT, `algorithm must be RS256 but got ${'HS256'}`)
      )
    })
  })

  describe('payload', () => {
    it.each([
      [
        'aud',
        {
          ...payload,
          aud: '',
        },
        new JwtError(JwtErrorCode.INVALID_ARGUMENT, '"aud" claim must be a string but got ""'),
      ],
      [
        'sub',
        {
          ...payload,
          sub: '',
        },
        new JwtError(JwtErrorCode.INVALID_ARGUMENT, '"sub" claim must be a string but got ""'),
      ],
      [
        'iss',
        {
          ...payload,
          iss: '',
        },
        new JwtError(JwtErrorCode.INVALID_ARGUMENT, '"iss" claim must be a string but got ""'),
      ],
      [
        'iat is in future',
        {
          ...payload,
          iat: currentTimestamp + 10000, // +10s
        },
        new JwtError(
          JwtErrorCode.INVALID_ARGUMENT,
          `Incorrect "iat" claim must be a older than "${currentTimestamp}" (iat: "${currentTimestamp + 10000}")`
        ),
      ],
      [
        'exp is in past',
        {
          ...payload,
          exp: currentTimestamp - 10000, // -10s
        },
        new JwtError(
          JwtErrorCode.INVALID_ARGUMENT,
          `Incorrect "exp" (expiration time) claim must be a newer than "${currentTimestamp}" (exp: "${
            currentTimestamp - 10000
          }")`
        ),
      ],
    ])('invalid %s', async (_, payload, wantErr) => {
      const testingKeyFetcher = await TestingKeyFetcher.withKeyPairGeneration('mismachKid')
      const jwt = await signJWT(kid, payload, testingKeyFetcher.getPrivateKey())
      expect(() => RS256Token.decode(jwt, currentTimestamp)).toThrowError(wantErr)
    })
  })
})
