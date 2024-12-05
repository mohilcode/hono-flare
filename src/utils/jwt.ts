import { ErrorCodes } from '../constants/error'
import { createError } from '../lib/error'
import { type JWTPayload, JWTPayloadSchema, type Token, TokenSchema } from '../types/auth'
import { HttpStatusCode } from '../types/http'
import { generateId } from './crypto'

const ACCESS_TOKEN_EXPIRY = 15 * 60

/**
 * Encode data to base64url format
 */
const base64UrlEncode = (data: string): string => {
  return btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Decode base64url to string
 */
const base64UrlDecode = (data: string): string => {
  const padding = '='.repeat((4 - (data.length % 4)) % 4)
  const base64 = (data + padding).replace(/-/g, '+').replace(/_/g, '/')
  return atob(base64)
}

/**
 * Generate JWT header
 */
const generateHeader = () => ({
  alg: 'RS256',
  typ: 'JWT',
})

/**
 * Generate JWT token with provided payload
 */
export const generateToken = async (
  payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'>,
  privateKey: CryptoKey
): Promise<string> => {
  try {
    const now = Math.floor(Date.now() / 1000)
    const completePayload = {
      ...payload,
      iat: now,
      exp: now + ACCESS_TOKEN_EXPIRY,
      jti: generateId(),
    }

    const header = generateHeader()
    const headerBase64 = base64UrlEncode(JSON.stringify(header))
    const payloadBase64 = base64UrlEncode(JSON.stringify(completePayload))
    const signingInput = `${headerBase64}.${payloadBase64}`

    const signature = await crypto.subtle.sign(
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      privateKey,
      new TextEncoder().encode(signingInput)
    )

    const signatureBase64 = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)))

    return `${headerBase64}.${payloadBase64}.${signatureBase64}`
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Token generation failed',
      { error }
    )
  }
}

/**
 * Verify and decode JWT token
 */
export const verifyToken = async (token: string, publicKey: CryptoKey): Promise<JWTPayload> => {
  try {
    const [headerB64, payloadB64, signatureB64] = token.split('.')
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error('Invalid token format')
    }

    const signingInput = `${headerB64}.${payloadB64}`
    const signatureData = atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/'))
    const signatureArray = new Uint8Array(signatureData.length)
    for (let i = 0; i < signatureData.length; i++) {
      signatureArray[i] = signatureData.charCodeAt(i)
    }

    const isValid = await crypto.subtle.verify(
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      publicKey,
      signatureArray,
      new TextEncoder().encode(signingInput)
    )

    if (!isValid) {
      throw new Error('Invalid token signature')
    }

    const payload = JSON.parse(base64UrlDecode(payloadB64))

    const now = Math.floor(Date.now() / 1000)
    if (payload.exp <= now) {
      throw new Error('Token has expired')
    }

    const validatedPayload = JWTPayloadSchema.parse(payload)
    return validatedPayload
  } catch (error) {
    throw createError(
      ErrorCodes.INVALID_TOKEN,
      HttpStatusCode.UNAUTHORIZED,
      'Token verification failed',
      { error }
    )
  }
}

/**
 * Generate key pair for JWT signing
 */
export const generateKeyPair = async (): Promise<CryptoKeyPair> => {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]).buffer,
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign', 'verify']
    )

    if (!('publicKey' in keyPair)) {
      throw new Error('Failed to generate key pair')
    }

    return keyPair
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Key pair generation failed',
      { error }
    )
  }
}

/**
 * Export public key in SPKI format
 */
export const exportPublicKey = async (publicKey: CryptoKey): Promise<string> => {
  try {
    const exported = await crypto.subtle.exportKey('spki', publicKey)
    const exportedArray = new Uint8Array(exported as ArrayBuffer)
    const exportedString = String.fromCharCode(...exportedArray)
    return base64UrlEncode(exportedString)
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Public key export failed',
      { error }
    )
  }
}

/**
 * Import public key from SPKI format
 */
export const importPublicKey = async (keyData: string): Promise<CryptoKey> => {
  try {
    const binaryString = atob(keyData)
    const binaryArray = new Uint8Array(binaryString.length)
    for (let i = 0; i < binaryString.length; i++) {
      binaryArray[i] = binaryString.charCodeAt(i)
    }

    return await crypto.subtle.importKey(
      'spki',
      binaryArray.buffer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      true,
      ['verify']
    )
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Public key import failed',
      { error }
    )
  }
}

/**
 * Generate authentication tokens
 */
export const generateAuthTokens = async (
  payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'>,
  privateKey: CryptoKey
): Promise<Token> => {
  const accessToken = await generateToken(payload, privateKey)
  const refreshToken = generateId()

  return TokenSchema.parse({
    accessToken,
    refreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY,
  })
}

/**
 * Check if token is blacklisted
 */
export const isTokenBlacklisted = async (jti: string, kv: KVNamespace): Promise<boolean> => {
  const blacklisted = await kv.get(`blacklist:${jti}`)
  return blacklisted !== null
}

/**
 * Blacklist a token
 */
export const blacklistToken = async (jti: string, exp: number, kv: KVNamespace): Promise<void> => {
  const now = Math.floor(Date.now() / 1000)
  const ttl = exp - now
  if (ttl > 0) {
    await kv.put(`blacklist:${jti}`, '1', { expirationTtl: ttl })
  }
}
