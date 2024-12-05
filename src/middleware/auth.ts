import type { Context, Next } from 'hono'
import { getCookie } from 'hono/cookie'
import { HTTPException } from 'hono/http-exception'
import { ErrorCodes } from '../constants/error'
import { BEARER_PREFIX, CSRF_COOKIE, CSRF_HEADER } from '../constants/services'
import { createError } from '../lib/error'
import { validateSession } from '../services/auth'
import type { JWTPayload } from '../types/auth'
import { HttpStatusCode } from '../types/http'
import { verifyCsrfToken } from '../utils/crypto'
import { isTokenBlacklisted, verifyToken } from '../utils/jwt'

interface AuthHonoContext extends Context {
  get(key: 'jwtPayload'): JWTPayload
  get(key: 'userId'): string
  get(key: 'sessionId'): string
  set(key: 'jwtPayload', value: JWTPayload): void
  set(key: 'userId', value: string): void
  set(key: 'sessionId', value: string): void
}

/**
 * Extract bearer token from Authorization header
 */
const extractBearerToken = (authHeader: string | undefined): string => {
  if (!authHeader?.startsWith(BEARER_PREFIX)) {
    throw createError(
      ErrorCodes.INVALID_TOKEN,
      HttpStatusCode.UNAUTHORIZED,
      'Invalid authorization header'
    )
  }
  return authHeader.slice(BEARER_PREFIX.length)
}

/**
 * Rate limiting middleware
 */
export const rateLimiter = async (c: Context, next: Next) => {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  const endpoint = `${c.req.method}:${c.req.path}`
  const key = `ratelimit:${ip}:${endpoint}`

  const current = await c.env.KV.get(key)
  const limit = 100
  const window = 60

  if (current && Number.parseInt(current) >= limit) {
    throw createError(
      ErrorCodes.RATE_LIMIT_EXCEEDED,
      HttpStatusCode.TOO_MANY_REQUESTS,
      'Rate limit exceeded'
    )
  }

  if (!current) {
    await c.env.KV.put(key, '1', { expirationTtl: window })
  } else {
    await c.env.KV.put(key, (Number.parseInt(current) + 1).toString(), {
      expirationTtl: window,
    })
  }

  await next()
}

/**
 * JWT authentication middleware
 */
export const jwtAuth = (publicKey: CryptoKey) => {
  return async (c: AuthHonoContext, next: Next) => {
    try {
      const authHeader = c.req.header('Authorization')
      const token = extractBearerToken(authHeader)

      const payload = await verifyToken(token, publicKey)

      if (await isTokenBlacklisted(payload.jti, c.env.KV)) {
        throw createError(
          ErrorCodes.INVALID_TOKEN,
          HttpStatusCode.UNAUTHORIZED,
          'Token has been revoked'
        )
      }

      c.set('jwtPayload', payload)
      c.set('userId', payload.sub)

      await next()
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error
      }
      throw createError(ErrorCodes.INVALID_TOKEN, HttpStatusCode.UNAUTHORIZED, 'Invalid token')
    }
  }
}

/**
 * Session authentication middleware
 */
export const sessionAuth = async (c: AuthHonoContext, next: Next) => {
  try {
    const sessionId = getCookie(c, 'session_id')
    const userId = c.get('userId')

    if (!sessionId) {
      throw createError(ErrorCodes.UNAUTHORIZED, HttpStatusCode.UNAUTHORIZED, 'No session found')
    }

    const session = await validateSession(c.env.KV, sessionId, userId)
    if (!session) {
      throw createError(ErrorCodes.UNAUTHORIZED, HttpStatusCode.UNAUTHORIZED, 'Invalid session')
    }

    c.set('sessionId', sessionId)

    await next()
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error
    }
    throw createError(
      ErrorCodes.UNAUTHORIZED,
      HttpStatusCode.UNAUTHORIZED,
      'Session validation failed'
    )
  }
}

/**
 * CSRF protection middleware
 */
export const csrfProtection = async (c: Context, next: Next) => {
  if (c.req.method === 'GET' || c.req.method === 'HEAD') {
    await next()
    return
  }

  const token = c.req.header(CSRF_HEADER)
  const storedToken = getCookie(c, CSRF_COOKIE)

  if (!token || !storedToken || !verifyCsrfToken(token, storedToken)) {
    throw createError(ErrorCodes.INVALID_REQUEST, HttpStatusCode.FORBIDDEN, 'Invalid CSRF token')
  }

  await next()
}

/**
 * Role-based access control middleware
 */
export const requireRole = (allowedRoles: string[]) => {
  return async (c: AuthHonoContext, next: Next) => {
    const payload = c.get('jwtPayload')

    if (!allowedRoles.includes(payload.role)) {
      throw createError(ErrorCodes.FORBIDDEN, HttpStatusCode.FORBIDDEN, 'Insufficient permissions')
    }

    await next()
  }
}

/**
 * Origin validation middleware
 */
export const validateOrigin = (allowedOrigins: string[]) => {
  return async (c: Context, next: Next) => {
    const origin = c.req.header('Origin')

    if (origin && !allowedOrigins.includes(origin)) {
      throw createError(ErrorCodes.FORBIDDEN, HttpStatusCode.FORBIDDEN, 'Invalid origin')
    }

    await next()
  }
}

/**
 * Combine multiple authentication middlewares
 */
export const authenticate = (publicKey: CryptoKey) => {
  return async (c: AuthHonoContext, next: Next) => {
    await jwtAuth(publicKey)(c, async () => {
      await sessionAuth(c, next)
    })
  }
}

/**
 * Email verification middleware
 */
export const requireEmailVerified = async (c: Context, next: Next) => {
  const user = c.get('user')

  if (!user.emailVerified) {
    throw createError(ErrorCodes.FORBIDDEN, HttpStatusCode.FORBIDDEN, 'Email verification required')
  }

  await next()
}
