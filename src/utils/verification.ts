import { RATE_LIMIT_PREFIX, TOKEN_PREFIX } from '../constants/services'
import { ValidationError } from '../types/error'

/**
 * Validate token format
 */
export const isValidToken = (token: string): boolean => {
  if (!token) {
    throw new ValidationError('Token is required')
  }

  const tokenRegex = /^[A-Za-z0-9_-]{21,}$/
  return tokenRegex.test(token)
}

/**
 * Get verification key for KV store
 */
export const getVerificationKey = (token: string): string => {
  if (!token) {
    throw new ValidationError('Token is required')
  }
  return `${TOKEN_PREFIX}${token}`
}

/**
 * Get rate limit key for KV store
 */
export const getRateLimitKey = (identifier: string): string => {
  if (!identifier) {
    throw new ValidationError('Identifier is required')
  }
  return `${RATE_LIMIT_PREFIX}${identifier}`
}
