import {
  RATE_LIMIT_MAX,
  RATE_LIMIT_PREFIX,
  RATE_LIMIT_WINDOW,
  TOKEN_EXPIRY,
  TOKEN_PREFIX,
} from '../constants/services'
import type {
  RateLimitInfo,
  VerificationResult,
  VerificationToken,
  VerificationTokenMetadata,
} from '../types/auth'
import { AuthenticationError, RateLimitError, ValidationError } from '../types/error'
import { generateId } from '../utils/crypto'

/**
 * Generate verification token
 */
export const generateVerificationToken = async (
  kv: KVNamespace,
  userId: string,
  email: string,
  metadata?: Pick<VerificationTokenMetadata, 'ipAddress' | 'userAgent'>
): Promise<string> => {
  const token = generateId()
  const verificationData: VerificationToken = {
    token,
    userId,
    email,
    createdAt: Date.now(),
    metadata: {
      attempts: 0,
      lastAttempt: Date.now(),
      ...metadata,
    },
  }

  await kv.put(`${TOKEN_PREFIX}${token}`, JSON.stringify(verificationData), {
    expirationTtl: TOKEN_EXPIRY,
  })

  return token
}

/**
 * Verify token and return verification result
 */
export const verifyToken = async (kv: KVNamespace, token: string): Promise<VerificationResult> => {
  const data = await kv.get(`${TOKEN_PREFIX}${token}`)

  if (!data) {
    return {
      success: false,
      error: 'Token not found or expired',
    }
  }

  const verificationData = JSON.parse(data) as VerificationToken

  const tokenAge = Date.now() - verificationData.createdAt
  if (tokenAge > TOKEN_EXPIRY * 1000) {
    await kv.delete(`${TOKEN_PREFIX}${token}`)
    return {
      success: false,
      error: 'Token has expired',
    }
  }

  if (verificationData.metadata.attempts >= 3) {
    return {
      success: false,
      error: 'Maximum verification attempts exceeded',
    }
  }

  const updatedData: VerificationToken = {
    ...verificationData,
    metadata: {
      ...verificationData.metadata,
      attempts: verificationData.metadata.attempts + 1,
      lastAttempt: Date.now(),
    },
  }

  await kv.put(`${TOKEN_PREFIX}${token}`, JSON.stringify(updatedData), {
    expirationTtl: TOKEN_EXPIRY,
  })

  await kv.delete(`${TOKEN_PREFIX}${token}`)

  return {
    success: true,
    userId: verificationData.userId,
    email: verificationData.email,
  }
}

/**
 * Check rate limit for verification attempts
 */
export const checkRateLimit = async (
  kv: KVNamespace,
  identifier: string
): Promise<RateLimitInfo> => {
  const key = `${RATE_LIMIT_PREFIX}${identifier}`
  const current = await kv.get(key)
  const attempts = current ? Number.parseInt(current, 10) : 0

  if (attempts >= RATE_LIMIT_MAX) {
    throw new RateLimitError('Too many verification attempts', {
      remaining: 0,
      reset: RATE_LIMIT_WINDOW,
      limit: RATE_LIMIT_MAX,
    })
  }

  await kv.put(key, (attempts + 1).toString(), { expirationTtl: RATE_LIMIT_WINDOW })

  return {
    remaining: RATE_LIMIT_MAX - (attempts + 1),
    reset: RATE_LIMIT_WINDOW,
    limit: RATE_LIMIT_MAX,
  }
}

/**
 * Generate verification URL
 */
export const generateVerificationUrl = (token: string, baseUrl: string): string => {
  const url = new URL('/auth/verify', baseUrl)
  url.searchParams.set('token', token)
  return url.toString()
}

/**
 * Create verification token with rate limiting
 */
export const createVerificationToken = async (
  kv: KVNamespace,
  userId: string,
  email: string,
  baseUrl: string,
  metadata?: Pick<VerificationTokenMetadata, 'ipAddress' | 'userAgent'>
): Promise<{ token: string; verificationUrl: string }> => {
  await checkRateLimit(kv, email)

  const token = await generateVerificationToken(kv, userId, email, metadata)
  const verificationUrl = generateVerificationUrl(token, baseUrl)

  return { token, verificationUrl }
}

/**
 * Validate token format
 */
export const isValidToken = (token: string): boolean => {
  const tokenRegex = /^[A-Za-z0-9_-]{21,}$/
  if (!tokenRegex.test(token)) {
    throw new ValidationError('Invalid token format')
  }
  return true
}

/**
 * Get all pending verification tokens for a user
 */
export const getPendingVerifications = async (
  kv: KVNamespace,
  userId: string
): Promise<VerificationToken[]> => {
  const tokens: VerificationToken[] = []
  const { keys } = await kv.list({ prefix: `${TOKEN_PREFIX}${userId}:` })

  for (const key of keys) {
    const data = await kv.get(key.name)
    if (data) {
      const token = JSON.parse(data) as VerificationToken
      tokens.push(token)
    }
  }

  return tokens
}

/**
 * Cancel verification token
 */
export const cancelVerification = async (
  kv: KVNamespace,
  token: string,
  userId: string
): Promise<void> => {
  const data = await kv.get(`${TOKEN_PREFIX}${token}`)

  if (!data) {
    throw new ValidationError('Token not found')
  }

  const verificationData = JSON.parse(data) as VerificationToken

  if (verificationData.userId !== userId) {
    throw new AuthenticationError('Unauthorized token access')
  }

  await kv.delete(`${TOKEN_PREFIX}${token}`)
}

/**
 * Clean up expired tokens
 */
export const cleanupExpiredTokens = async (kv: KVNamespace): Promise<void> => {
  const { keys } = await kv.list({ prefix: TOKEN_PREFIX })
  const now = Date.now()

  for (const key of keys) {
    const data = await kv.get(key.name)
    if (data) {
      const token = JSON.parse(data) as VerificationToken
      if (now - token.createdAt > TOKEN_EXPIRY * 1000) {
        await kv.delete(key.name)
      }
    }
  }
}

export const verificationService = {
  generateToken: generateVerificationToken,
  verifyToken,
  checkRateLimit,
  generateVerificationUrl,
  createVerificationToken,
  isValidToken,
  getPendingVerifications,
  cancelVerification,
  cleanupExpiredTokens,
}
