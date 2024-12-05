import { ErrorCodes } from '../constants/error'
import {
  RATE_LIMIT_MAX,
  RATE_LIMIT_PREFIX,
  RATE_LIMIT_WINDOW,
  TOKEN_EXPIRY,
  TOKEN_PREFIX,
} from '../constants/services'
import { createError } from '../lib/error'
import type { RateLimitInfo, VerificationResult, VerificationToken } from '../types/auth'
import type { HttpStatus } from '../types/http'
import { generateId } from '../utils/crypto'

export const generateVerificationToken = async (
  kv: KVNamespace,
  userId: string,
  email: string
): Promise<string> => {
  const token = generateId()
  const verificationData: VerificationToken = {
    token,
    userId,
    email,
    createdAt: Date.now(),
  }

  await kv.put(`${TOKEN_PREFIX}${token}`, JSON.stringify(verificationData), {
    expirationTtl: TOKEN_EXPIRY,
  })

  return token
}

export const verifyToken = async (kv: KVNamespace, token: string): Promise<VerificationResult> => {
  try {
    const data = await kv.get(`${TOKEN_PREFIX}${token}`)

    if (!data) {
      return {
        success: false,
        error: 'Token not found or expired',
      }
    }

    const verificationData = JSON.parse(data) as VerificationToken

    await kv.delete(`${TOKEN_PREFIX}${token}`)

    return {
      success: true,
      userId: verificationData.userId,
      email: verificationData.email,
    }
  } catch (_error) {
    return {
      success: false,
      error: 'Invalid verification token',
    }
  }
}

export const checkRateLimit = async (
  kv: KVNamespace,
  identifier: string
): Promise<RateLimitInfo> => {
  const key = `${RATE_LIMIT_PREFIX}${identifier}`
  const current = await kv.get(key)
  const attempts = current ? Number.parseInt(current, 10) : 0

  if (attempts >= RATE_LIMIT_MAX) {
    throw createError(
      ErrorCodes.RATE_LIMIT_EXCEEDED,
      429 as HttpStatus,
      'Too many verification attempts. Please try again later.'
    )
  }

  await kv.put(key, (attempts + 1).toString(), { expirationTtl: RATE_LIMIT_WINDOW })

  return {
    remaining: RATE_LIMIT_MAX - (attempts + 1),
    reset: RATE_LIMIT_WINDOW,
    limit: RATE_LIMIT_MAX,
  }
}

export const generateVerificationUrl = (token: string, baseUrl: string): string => {
  const url = new URL('/auth/verify', baseUrl)
  url.searchParams.set('token', token)
  return url.toString()
}

export const createVerificationToken = async (
  kv: KVNamespace,
  userId: string,
  email: string,
  baseUrl: string
): Promise<{ token: string; verificationUrl: string }> => {
  await checkRateLimit(kv, email)

  const token = await generateVerificationToken(kv, userId, email)

  const verificationUrl = generateVerificationUrl(token, baseUrl)

  return { token, verificationUrl }
}
