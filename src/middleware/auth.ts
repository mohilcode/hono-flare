import type { Context, Next } from 'hono'
import { getCookie } from 'hono/cookie'
import { BEARER_PREFIX, CSRF_COOKIE, CSRF_HEADER } from '../constants/services'
import { validateSession } from '../services/auth'
import type { AuthHonoContext } from '../types/auth'
import {
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  ValidationError,
} from '../types/error'
import { verifyCsrfToken } from '../utils/crypto'
import { isTokenBlacklisted, verifyJWTToken } from '../utils/jwt'

const _extractBearerToken = (authHeader: string | undefined): string => {
  if (!authHeader?.startsWith(BEARER_PREFIX)) {
    throw new AuthenticationError('Invalid authorization header')
  }
  return authHeader.slice(BEARER_PREFIX.length)
}

export const rateLimiter = async (c: Context, next: Next) => {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  const endpoint = `${c.req.method}:${c.req.path}`
  const key = `ratelimit:${ip}:${endpoint}`

  const current = await c.env.KV.get(key)
  const limit = 100
  const window = 60

  if (current && Number.parseInt(current) >= limit) {
    throw new RateLimitError('Rate limit exceeded', {
      limit,
      window,
      remaining: 0,
      resetAt: Date.now() + window * 1000,
    })
  }

  if (!current) {
    await c.env.KV.put(key, '1', { expirationTtl: window })
  } else {
    const newValue = (Number.parseInt(current) + 1).toString()
    await c.env.KV.put(key, newValue, { expirationTtl: window })
  }

  await next()
}

const _jwtAuth = (publicKey: CryptoKey) => {
  return async (c: AuthHonoContext, next: Next) => {
    const authHeader = c.req.header('Authorization')
    if (!authHeader) {
      throw new AuthenticationError('Authorization header is required')
    }

    const token = _extractBearerToken(authHeader)
    const payload = await verifyJWTToken(token, publicKey)

    if (!payload.jti) {
      throw new AuthenticationError('Invalid token: missing JTI')
    }

    if (await isTokenBlacklisted(payload.jti, c.env.KV)) {
      throw new AuthenticationError('Token has been revoked')
    }

    c.set('jwtPayload', payload)
    c.set('userId', payload.sub)

    await next()
  }
}

const _sessionAuth = async (c: AuthHonoContext, next: Next) => {
  const sessionId = getCookie(c, 'session_id')
  if (!sessionId) {
    throw new AuthenticationError('No session found')
  }

  const userId = c.get('userId')
  if (!userId) {
    throw new AuthenticationError('User ID not found in context')
  }

  const session = await validateSession(c.env.KV, sessionId, userId)
  if (!session) {
    throw new AuthenticationError('Invalid or expired session')
  }

  c.set('sessionId', sessionId)
  await next()
}

export const csrfProtection = async (c: Context, next: Next) => {
  if (c.req.method === 'GET' || c.req.method === 'HEAD' || c.req.method === 'OPTIONS') {
    await next()
    return
  }

  const token = c.req.header(CSRF_HEADER)
  const storedToken = getCookie(c, CSRF_COOKIE)

  if (!token || !storedToken) {
    throw new AuthorizationError('CSRF token missing')
  }

  if (!verifyCsrfToken(token, storedToken)) {
    throw new AuthorizationError('Invalid CSRF token')
  }

  await next()
}

export const authenticate = (publicKey: CryptoKey) => {
  return async (c: AuthHonoContext, next: Next) => {
    await _jwtAuth(publicKey)(c, async () => {
      await _sessionAuth(c, next)
    })
  }
}

export const _requireRole = (allowedRoles: string[]) => {
  return async (c: AuthHonoContext, next: Next) => {
    const payload = c.get('jwtPayload')
    if (!payload.role) {
      throw new AuthorizationError('Role information missing')
    }

    if (!allowedRoles.includes(payload.role)) {
      throw new AuthorizationError('Insufficient permissions', {
        required: allowedRoles,
        current: payload.role,
      })
    }

    await next()
  }
}

export const _validateOrigin = (allowedOrigins: string[]) => {
  return async (c: Context, next: Next) => {
    const origin = c.req.header('Origin')
    if (!origin) {
      throw new ValidationError('Origin header is required')
    }

    if (!allowedOrigins.includes(origin)) {
      throw new AuthorizationError('Invalid origin', {
        origin,
        allowed: allowedOrigins,
      })
    }

    await next()
  }
}

export const _requireEmailVerified = async (c: AuthHonoContext, next: Next) => {
  const user = c.get('user')
  if (!user?.emailVerified) {
    throw new AuthenticationError('Email verification required')
  }

  await next()
}
