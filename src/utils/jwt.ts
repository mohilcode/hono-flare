import { ACCESS_TOKEN_EXPIRY } from '../constants/services'
import { type JWTPayload, JWTPayloadSchema, type Token, TokenSchema } from '../types/auth'
import { AuthenticationError, ValidationError } from '../types/error'
import { generateId } from './crypto'

// Key cache
let _privateKey: CryptoKey | null = null
let _publicKey: CryptoKey | null = null

const _pemToBuffer = (pem: string): ArrayBuffer => {
  const base64 = pem
    .replace(/-----BEGIN.*?-----/g, '')
    .replace(/-----END.*?-----/g, '')
    .replace(/\s+/g, '')

  const binary = atob(base64)
  const buffer = new ArrayBuffer(binary.length)
  const bytes = new Uint8Array(buffer)

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }

  return buffer
}

const _base64UrlEncode = (data: string): string => {
  return btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const _base64UrlDecode = (data: string): string => {
  if (!/^[A-Za-z0-9_-]+$/.test(data)) {
    throw new ValidationError('Invalid base64url format')
  }

  const padding = '='.repeat((4 - (data.length % 4)) % 4)
  const base64 = (data + padding).replace(/-/g, '+').replace(/_/g, '/')
  return atob(base64)
}

const _generateHeader = () => ({
  alg: 'RS256',
  typ: 'JWT',
})

const _importKeys = async (env: CloudflareBindings) => {
  if (!_privateKey || !_publicKey) {
    const privateKeyBuffer = _pemToBuffer(env.JWT_PRIVATE_KEY)
    const publicKeyBuffer = _pemToBuffer(env.JWT_PUBLIC_KEY)

    _privateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign']
    )

    _publicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      true,
      ['verify']
    )
  }

  return { privateKey: _privateKey, publicKey: _publicKey }
}

export const getSigningKey = async (env: CloudflareBindings): Promise<CryptoKey> => {
  const { privateKey } = await _importKeys(env)
  return privateKey
}

export const getVerificationKey = async (env: CloudflareBindings): Promise<CryptoKey> => {
  const { publicKey } = await _importKeys(env)
  return publicKey
}

const _generateToken = async (
  payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'>,
  env: CloudflareBindings
): Promise<string> => {
  if (!payload.sub || !payload.email) {
    throw new ValidationError('Invalid payload: sub and email are required')
  }

  const privateKey = await getSigningKey(env)
  const now = Math.floor(Date.now() / 1000)
  const completePayload = {
    ...payload,
    iat: now,
    exp: now + ACCESS_TOKEN_EXPIRY,
    jti: generateId(),
  }

  const header = _generateHeader()
  const headerBase64 = _base64UrlEncode(JSON.stringify(header))
  const payloadBase64 = _base64UrlEncode(JSON.stringify(completePayload))
  const signingInput = `${headerBase64}.${payloadBase64}`

  const signature = await crypto.subtle.sign(
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' },
    },
    privateKey,
    new TextEncoder().encode(signingInput)
  )

  const signatureBase64 = _base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)))

  return `${headerBase64}.${payloadBase64}.${signatureBase64}`
}

export const verifyJWTToken = async (
  token: string,
  env: CloudflareBindings
): Promise<JWTPayload> => {
  const tokenParts = token.split('.')
  if (tokenParts.length !== 3) {
    throw new ValidationError('Invalid token format')
  }

  const [headerB64, payloadB64, signatureB64] = tokenParts
  const signingInput = `${headerB64}.${payloadB64}`

  const signatureData = atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/'))
  const signatureArray = new Uint8Array(signatureData.length)
  for (let i = 0; i < signatureData.length; i++) {
    signatureArray[i] = signatureData.charCodeAt(i)
  }

  const publicKey = await getVerificationKey(env)
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

  const payload = JSON.parse(_base64UrlDecode(payloadB64))
  const now = Math.floor(Date.now() / 1000)

  if (payload.exp <= now) {
    throw new AuthenticationError('Token has expired')
  }

  return JWTPayloadSchema.parse(payload)
}

export const generateAuthTokens = async (
  payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'>,
  env: CloudflareBindings
): Promise<Token> => {
  const accessToken = await _generateToken(payload, env)
  const refreshToken = generateId()

  return TokenSchema.parse({
    accessToken,
    refreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY,
  })
}

export const isTokenBlacklisted = async (jti: string, kv: KVNamespace): Promise<boolean> => {
  if (!jti) {
    throw new ValidationError('JTI is required')
  }
  const blacklisted = await kv.get(`blacklist:${jti}`)
  return blacklisted !== null
}

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
