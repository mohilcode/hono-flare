import { type JWTPayload, JWTPayloadSchema, type Token, TokenSchema } from '../types/auth'
import { AuthenticationError, ValidationError } from '../types/error'
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
  if (!/^[A-Za-z0-9_-]+$/.test(data)) {
    throw new ValidationError('Invalid base64url format')
  }

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
  if (!payload.sub || !payload.email) {
    throw new ValidationError('Invalid payload: sub and email are required')
  }

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
}

/**
 * Verify and decode JWT token
 */
export const verifyToken = async (token: string, publicKey: CryptoKey): Promise<JWTPayload> => {
  const tokenParts = token.split('.')
  if (tokenParts.length !== 3) {
    throw new ValidationError('Invalid token format')
  }

  const [headerB64, payloadB64, signatureB64] = tokenParts
  const signingInput = `${headerB64}.${payloadB64}`

  // Verify signature
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
    throw new AuthenticationError('Invalid token signature')
  }

  // Verify and decode payload
  const payload = JSON.parse(base64UrlDecode(payloadB64))
  const now = Math.floor(Date.now() / 1000)

  if (payload.exp <= now) {
    throw new AuthenticationError('Token has expired')
  }

  return JWTPayloadSchema.parse(payload)
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
  if (!jti) {
    throw new ValidationError('JTI is required')
  }
  const blacklisted = await kv.get(`blacklist:${jti}`)
  return blacklisted !== null
}

/**
 * Blacklist a token
 */
export const blacklistToken = async (jti: string, exp: number, kv: KVNamespace): Promise<void> => {
  if (!jti || !exp) {
    throw new ValidationError('JTI and expiration are required')
  }

  const now = Math.floor(Date.now() / 1000)
  const ttl = exp - now
  if (ttl > 0) {
    await kv.put(`blacklist:${jti}`, '1', { expirationTtl: ttl })
  }
}
