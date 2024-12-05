import { eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { ErrorCodes } from '../constants/error'
import { COOKIE_OPTIONS, CSRF_COOKIE, REFRESH_COOKIE, SESSION_COOKIE } from '../constants/services'
import { createDB } from '../db'
import * as schema from '../db/schema'
import { createError } from '../lib/error'
import { authenticate, csrfProtection, rateLimiter } from '../middleware/auth'
import { loginUser, logoutUser, refreshAccessToken, registerUser } from '../services/auth'
import { createEmailConfig } from '../services/email'
import { initiatePasswordReset, resetPassword } from '../services/password'
import { createVerificationToken, verifyToken } from '../services/verification'
import {
  ForgotPasswordRequestSchema,
  JWTPayloadSchema,
  LoginRequestSchema,
  RegisterRequestSchema,
  ResetPasswordRequestSchema,
  type Variables,
} from '../types/auth'
import type { VerificationResult } from '../types/auth'
import { type HttpStatus, HttpStatusCode } from '../types/http'
import { generateCsrfToken } from '../utils/crypto'

const route = new Hono<{
  Bindings: CloudflareBindings
  Variables: Variables
}>()

/**
 * Register new user
 */
route.post('/register', rateLimiter, async c => {
  try {
    const data = await c.req.json()
    const baseUrl = new URL(c.req.url).origin
    const validatedData = RegisterRequestSchema.parse(data)

    const user = await registerUser(
      c.env.DB,
      c.env.KV,
      validatedData,
      baseUrl,
      c.env.RESEND_API_KEY
    )
    return c.json({ user }, HttpStatusCode.CREATED)
  } catch (error) {
    if (error instanceof Error) {
      throw createError(ErrorCodes.VALIDATION_ERROR, HttpStatusCode.BAD_REQUEST, error.message)
    }
    throw error
  }
})

/**
 * Login user
 */
route.post('/login', rateLimiter, async c => {
  try {
    const data = await c.req.json()
    const validatedData = LoginRequestSchema.parse(data)

    const userAgent = c.req.header('User-Agent')
    const ipAddress = c.req.header('CF-Connecting-IP')

    const keyPair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]).buffer,
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair

    const { user, token, session } = await loginUser(
      c.env.DB,
      c.env.KV,
      validatedData,
      keyPair.privateKey,
      userAgent,
      ipAddress
    )

    const csrfToken = generateCsrfToken()

    setCookie(c, SESSION_COOKIE, session.id, {
      ...COOKIE_OPTIONS,
      maxAge: 7 * 24 * 60 * 60,
    })

    setCookie(c, CSRF_COOKIE, csrfToken, COOKIE_OPTIONS)

    if (token.refreshToken) {
      setCookie(c, REFRESH_COOKIE, token.refreshToken, {
        ...COOKIE_OPTIONS,
        maxAge: 30 * 24 * 60 * 60,
      })
    }

    return c.json({
      user,
      token: {
        accessToken: token.accessToken,
        expiresIn: token.expiresIn,
      },
      csrfToken,
    })
  } catch (error) {
    if (error instanceof Error) {
      throw createError(ErrorCodes.VALIDATION_ERROR, HttpStatusCode.BAD_REQUEST, error.message)
    }
    throw error
  }
})

/**
 * Logout user
 */
route.post('/logout', async c => {
  try {
    const keyPair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]).buffer,
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair

    await authenticate(keyPair.publicKey)(c, async () => {})
    await csrfProtection(c, async () => {})

    const userId = c.get('userId')
    const sessionId = c.get('sessionId')
    const payload = c.get('jwtPayload')

    await logoutUser(c.env.KV, sessionId, userId, payload.jti, payload.exp)

    deleteCookie(c, SESSION_COOKIE)
    deleteCookie(c, CSRF_COOKIE)
    deleteCookie(c, REFRESH_COOKIE)

    return c.json({ message: 'Logged out successfully' })
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Logout failed',
      { error }
    )
  }
})

/**
 * Refresh access token
 */
route.post('/refresh', rateLimiter, async c => {
  try {
    const refreshToken = getCookie(c, REFRESH_COOKIE)
    if (!refreshToken) {
      throw createError(ErrorCodes.INVALID_TOKEN, HttpStatusCode.UNAUTHORIZED, 'No refresh token')
    }

    const payload = JWTPayloadSchema.parse(JSON.parse(atob(refreshToken.split('.')[1])))

    const keyPair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]).buffer,
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair

    const newToken = await refreshAccessToken(
      c.env.DB,
      c.env.KV,
      refreshToken,
      payload.sub,
      keyPair.privateKey
    )

    if (newToken.refreshToken) {
      setCookie(c, REFRESH_COOKIE, newToken.refreshToken, {
        ...COOKIE_OPTIONS,
        maxAge: 30 * 24 * 60 * 60,
      })
    }

    return c.json({
      token: {
        accessToken: newToken.accessToken,
        expiresIn: newToken.expiresIn,
      },
    })
  } catch (error) {
    if (error instanceof Error) {
      throw createError(ErrorCodes.INVALID_TOKEN, HttpStatusCode.UNAUTHORIZED, error.message)
    }
    throw error
  }
})

/**
 * Get current session info
 */
route.get('/session', async c => {
  try {
    const keyPair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]).buffer,
        hash: { name: 'SHA-256' },
      },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair

    await authenticate(keyPair.publicKey)(c, async () => {})

    const payload = c.get('jwtPayload')
    return c.json({ session: payload })
  } catch (error) {
    throw createError(ErrorCodes.UNAUTHORIZED, HttpStatusCode.UNAUTHORIZED, 'Invalid session', {
      error,
    })
  }
})

/**
 * Resend verification email
 */
route.post('/resend', rateLimiter, async c => {
  const { email } = await c.req.json()
  if (!email) {
    throw createError(ErrorCodes.VALIDATION_ERROR, 400 as HttpStatus, 'Email is required')
  }

  const db = createDB(c.env)
  const user = await db.select().from(schema.users).where(eq(schema.users.email, email)).get()

  if (!user) {
    throw createError(ErrorCodes.USER_NOT_FOUND, 404 as HttpStatus, 'User not found')
  }

  if (user.emailVerified) {
    return c.json({ message: 'Email already verified' })
  }

  const baseUrl = new URL(c.req.url).origin
  const { verificationUrl } = await createVerificationToken(c.env.KV, user.id, email, baseUrl)

  const emailConfig = createEmailConfig(c.env.RESEND_API_KEY)
  await emailConfig.sendVerificationEmail({
    to: email,
    firstName: user.firstName,
    verificationUrl,
  })

  return c.json({ message: 'Verification email sent' })
})

/**
 * Verify Email
 */
route.get('/verify', async c => {
  try {
    const token = c.req.query('token')
    if (!token) {
      throw createError(
        ErrorCodes.VALIDATION_ERROR,
        400 as HttpStatus,
        'Verification token is required'
      )
    }

    const result: VerificationResult = await verifyToken(c.env.KV, token)

    if (!result.success) {
      throw createError(
        ErrorCodes.INVALID_TOKEN,
        400 as HttpStatus,
        result.error || 'Invalid verification token'
      )
    }

    if (!result.userId) {
      throw createError(
        ErrorCodes.INVALID_TOKEN,
        400 as HttpStatus,
        'Invalid verification token: missing user ID'
      )
    }

    const db = createDB(c.env)
    await db
      .update(schema.users)
      .set({ emailVerified: true })
      .where(eq(schema.users.id, result.userId))
      .run()

    return c.json(
      {
        success: true,
        message: 'Email verified successfully',
      },
      200
    )
  } catch (error) {
    if (error instanceof Error && 'code' in error) {
      throw error
    }
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Email verification failed',
      { error }
    )
  }
})

/**
 * Forgot password request
 */
route.post('/forgot-password', rateLimiter, async c => {
  try {
    const data = await c.req.json()
    const validatedData = ForgotPasswordRequestSchema.parse(data)

    const baseUrl = new URL(c.req.url).origin
    await initiatePasswordReset(c.env.DB, c.env.KV, validatedData, baseUrl, c.env.RESEND_API_KEY)

    return c.json({
      message: 'If your email is registered, you will receive password reset instructions',
    })
  } catch (error) {
    if (error instanceof Error) {
      throw createError(ErrorCodes.VALIDATION_ERROR, 400 as HttpStatus, error.message)
    }
    throw error
  }
})

/**
 * Reset password
 */
route.post('/reset-password', rateLimiter, async c => {
  try {
    const data = await c.req.json()
    const validatedData = ResetPasswordRequestSchema.parse(data)

    await resetPassword(c.env.DB, c.env.KV, validatedData, c.env.RESEND_API_KEY)

    return c.json({
      message: 'Password reset successful',
    })
  } catch (error) {
    if (error instanceof Error) {
      throw createError(ErrorCodes.VALIDATION_ERROR, 400 as HttpStatus, error.message)
    }
    throw error
  }
})

export default route
