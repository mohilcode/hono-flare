import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { z } from 'zod'
import {
  COOKIE_OPTIONS,
  CSRF_COOKIE,
  REFRESH_COOKIE,
  SESSION_COOKIE,
} from '../../constants/services'
import { createDB } from '../../db'
import { authenticate, csrfProtection, rateLimiter } from '../../middleware/auth'
import {
  getCurrentSession,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  resendVerificationEmail,
  verifyEmailToken,
} from '../../services/auth'
import { initiatePasswordReset, resetPassword } from '../../services/password'
import {
  ForgotPasswordRequestSchema,
  LoginRequestSchema,
  RegisterRequestSchema,
  ResetPasswordRequestSchema,
  type Variables,
} from '../../types/auth'
import { AuthenticationError, ValidationError } from '../../types/error'
import { validateOrThrow } from '../../types/error'
import { generateAuthKeyPair } from '../../utils/crypto'
import googleRoutes from './google'

const route = new Hono<{
  Bindings: CloudflareBindings
  Variables: Variables
}>()

/**
 * Register new user
 */
route.post('/register', rateLimiter, async c => {
  try {
    const db = createDB(c.env)
    const data = await c.req.json()
    const validatedData = validateOrThrow(RegisterRequestSchema, data)
    const baseUrl = new URL(c.req.url).origin

    const user = await registerUser({
      db,
      kv: c.env.KV,
      userData: validatedData,
      baseUrl,
      resendApiKey: c.env.RESEND_API_KEY,
    })

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
    const db = createDB(c.env)
    const data = await c.req.json()
    const validatedData = validateOrThrow(LoginRequestSchema, data)

    const { user, token, session, csrfToken } = await loginUser({
      db,
      kv: c.env.KV,
      loginData: validatedData,
      userAgent: c.req.header('User-Agent'),
      ipAddress: c.req.header('CF-Connecting-IP'),
    })

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

    await logoutUser({
      kv: c.env.KV,
      sessionId: c.get('sessionId'),
      userId: c.get('userId'),
      jti: c.get('jwtPayload').jti,
      exp: c.get('jwtPayload').exp,
    })

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
    const db = createDB(c.env)
    const refreshToken = getCookie(c, REFRESH_COOKIE)

    if (!refreshToken) {
      throw new AuthenticationError('No refresh token provided')
    }

    const token = await refreshAccessToken({
      db,
      kv: c.env.KV,
      refreshToken,
    })

    if (token.refreshToken) {
      setCookie(c, REFRESH_COOKIE, token.refreshToken, {
        ...COOKIE_OPTIONS,
        maxAge: 30 * 24 * 60 * 60,
      })
    }

    return c.json({
      token: {
        accessToken: token.accessToken,
        expiresIn: token.expiresIn,
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

    const sessionInfo = await getCurrentSession({
      jwtPayload: c.get('jwtPayload'),
      sessionId: c.get('sessionId'),
      userId: c.get('userId'),
    })

    return c.json({ session: sessionInfo })
  } catch (error) {
    throw error
  }
})

/**
 * Resend verification email
 */
route.post('/resend', rateLimiter, async c => {
  try {
    const db = createDB(c.env)
    const { email } = validateOrThrow(z.object({ email: z.string().email() }), await c.req.json())

    const baseUrl = new URL(c.req.url).origin

    await resendVerificationEmail({
      db,
      kv: c.env.KV,
      email,
      baseUrl,
      resendApiKey: c.env.RESEND_API_KEY,
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

    const db = createDB(c.env)
    await verifyEmailToken({
      db,
      kv: c.env.KV,
      token,
      resendApiKey: c.env.RESEND_API_KEY,
    })

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
    const db = createDB(c.env)
    const data = await c.req.json()
    const validatedData = validateOrThrow(ForgotPasswordRequestSchema, data)
    const baseUrl = new URL(c.req.url).origin

    await initiatePasswordReset({
      db,
      kv: c.env.KV,
      email: validatedData.email,
      baseUrl,
      resendApiKey: c.env.RESEND_API_KEY,
    })

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
    const db = createDB(c.env)
    const data = await c.req.json()
    const validatedData = validateOrThrow(ResetPasswordRequestSchema, data)

    await resetPassword({
      db,
      kv: c.env.KV,
      token: validatedData.token,
      newPassword: validatedData.password,
      resendApiKey: c.env.RESEND_API_KEY,
    })

    return c.json({
      message: 'Password reset successful',
    })
  } catch (error) {
    throw error
  }
})

route.route('/google', googleRoutes)

export default route
