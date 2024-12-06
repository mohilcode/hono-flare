import { eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { z } from 'zod'
import { COOKIE_OPTIONS, CSRF_COOKIE, REFRESH_COOKIE, SESSION_COOKIE } from '../constants/services'
import { createDB } from '../db'
import * as schema from '../db/schema'
import { authenticate, csrfProtection, rateLimiter } from '../middleware/auth'
import { loginUser, logoutUser, refreshAccessToken, registerUser } from '../services/auth'
import { createEmailConfig, getEmailDomain, isDisposableEmail } from '../services/email'
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
import {
  AuthenticationError,
  RateLimitError,
  ResourceNotFoundError,
  ValidationError,
} from '../types/error'
import { validateOrThrow } from '../types/error'
import { generateAuthKeyPair, generateCsrfToken } from '../utils/crypto'

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

    const validatedData = validateOrThrow(RegisterRequestSchema, data)

    const domain = getEmailDomain(validatedData.email)
    if (await isDisposableEmail(domain)) {
      throw new ValidationError('Disposable email addresses are not allowed')
    }

    const user = await registerUser(
      c.env.DB,
      c.env.KV,
      validatedData,
      baseUrl,
      c.env.RESEND_API_KEY
    )

    return c.json({ user }, 201)
  } catch (error) {
    throw error
  }
})

/**
 * Login user
 */
route.post('/login', rateLimiter, async c => {
  try {
    const data = await c.req.json()
    const validatedData = validateOrThrow(LoginRequestSchema, data)

    const userAgent = c.req.header('User-Agent')
    const ipAddress = c.req.header('CF-Connecting-IP')

    const keyPair = await generateAuthKeyPair()

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
    throw error
  }
})

/**
 * Logout user
 */
route.post('/logout', async c => {
  try {
    const keyPair = await generateAuthKeyPair()

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
    throw error
  }
})

/**
 * Refresh access token
 */
route.post('/refresh', rateLimiter, async c => {
  try {
    const refreshToken = getCookie(c, REFRESH_COOKIE)
    if (!refreshToken) {
      throw new AuthenticationError('No refresh token provided')
    }

    const payload = validateOrThrow(JWTPayloadSchema, JSON.parse(atob(refreshToken.split('.')[1])))

    const keyPair = await generateAuthKeyPair()

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
    throw error
  }
})

/**
 * Get current session info
 */
route.get('/session', async c => {
  try {
    const keyPair = await generateAuthKeyPair()

    await authenticate(keyPair.publicKey)(c, async () => {})

    const payload = c.get('jwtPayload')
    return c.json({ session: payload })
  } catch (error) {
    throw error
  }
})

/**
 * Resend verification email
 */
route.post('/resend', rateLimiter, async c => {
  try {
    const { email } = validateOrThrow(z.object({ email: z.string().email() }), await c.req.json())

    const domain = getEmailDomain(email)
    if (await isDisposableEmail(domain)) {
      throw new ValidationError('Disposable email addresses are not allowed')
    }

    const emailConfig = createEmailConfig(c.env.RESEND_API_KEY)
    if (!emailConfig.validateEmail(email)) {
      throw new ValidationError('Invalid email format')
    }

    // Check rate limit specifically for email
    if (!(await emailConfig.checkRateLimit(c.env.KV, email))) {
      throw new RateLimitError('Too many verification attempts', {
        resetIn: '1 hour',
        maxAttempts: 5,
      })
    }

    const db = createDB(c.env)
    const user = await db.select().from(schema.users).where(eq(schema.users.email, email)).get()

    if (!user) {
      throw new ResourceNotFoundError('User not found')
    }

    if (user.emailVerified) {
      return c.json({ message: 'Email already verified' })
    }

    const baseUrl = new URL(c.req.url).origin
    const { verificationUrl } = await createVerificationToken(c.env.KV, user.id, email, baseUrl)

    await emailConfig.sendVerificationEmail({
      to: email,
      firstName: user.firstName,
      verificationUrl,
    })

    return c.json({ message: 'Verification email sent' })
  } catch (error) {
    throw error
  }
})

/**
 * Verify Email
 */
route.get('/verify', async c => {
  try {
    const token = c.req.query('token')
    if (!token) {
      throw new ValidationError('Verification token is required')
    }

    const result = await verifyToken(c.env.KV, token)

    if (!result.success) {
      throw new ValidationError(result.error || 'Invalid verification token')
    }

    if (!result.userId) {
      throw new ValidationError('Invalid verification token: missing user ID')
    }

    const db = createDB(c.env)
    await db
      .update(schema.users)
      .set({ emailVerified: true })
      .where(eq(schema.users.id, result.userId))
      .run()

    return c.json({
      success: true,
      message: 'Email verified successfully',
    })
  } catch (error) {
    throw error
  }
})

/**
 * Forgot password request
 */
route.post('/forgot-password', rateLimiter, async c => {
  try {
    const data = await c.req.json()
    const validatedData = validateOrThrow(ForgotPasswordRequestSchema, data)

    const baseUrl = new URL(c.req.url).origin
    await initiatePasswordReset(c.env.DB, c.env.KV, validatedData, baseUrl, c.env.RESEND_API_KEY)

    return c.json({
      message: 'If your email is registered, you will receive password reset instructions',
    })
  } catch (error) {
    throw error
  }
})

/**
 * Reset password
 */
route.post('/reset-password', rateLimiter, async c => {
  try {
    const data = await c.req.json()
    const validatedData = validateOrThrow(ResetPasswordRequestSchema, data)

    await resetPassword(c.env.DB, c.env.KV, validatedData, c.env.RESEND_API_KEY)

    return c.json({
      message: 'Password reset successful',
    })
  } catch (error) {
    throw error
  }
})

export default route
