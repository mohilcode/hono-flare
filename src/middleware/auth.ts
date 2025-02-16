import type { Context, Next } from 'hono'
import { getCookie } from 'hono/cookie'
import {
  ACCESS_TOKEN_COOKIE,
  CSRF_COOKIE,
  CSRF_HEADER,
  SESSION_COOKIE,
} from '../constants/services'
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

export const authenticate = () => {
  return async (c: AuthHonoContext, next: Next) => {
    const accessToken = getCookie(c, ACCESS_TOKEN_COOKIE)
    if (!accessToken) {
      throw new AuthenticationError('Authentication required')
    }

    const payload = await verifyJWTToken(accessToken, c.env)

    if (!payload.jti) {
      throw new AuthenticationError('Invalid token: missing JTI')
    }

    if (await isTokenBlacklisted(payload.jti, c.env.KV)) {
      throw new AuthenticationError('Token has been revoked')
    }

    c.set('jwtPayload', payload)
    c.set('userId', payload.sub)

    const sessionId = getCookie(c, SESSION_COOKIE)
    if (!sessionId) {
      throw new AuthenticationError('No session found')
    }

    const session = await validateSession(c.env.KV, sessionId, payload.sub)
    if (!session) {
      throw new AuthenticationError('Invalid or expired session')
    }

    c.set('sessionId', sessionId)
    await next()
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
