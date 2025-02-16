import { googleAuth } from '@hono/oauth-providers/google'
import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import { COOKIE_OPTIONS, CSRF_COOKIE, SESSION_COOKIE } from '../../constants/services'
import { createDB } from '../../db'
import { rateLimiter } from '../../middleware/auth'
import { handleGoogleAuth } from '../../services/google'
import { generateCsrfToken } from '../../utils/crypto'

const router = new Hono<{ Bindings: CloudflareBindings }>()

/**
 * Google OAuth
 */
router.get('/', rateLimiter, async (c, next) => {
  const middleware = googleAuth({
    scope: ['email', 'profile'],
    client_id: c.env.GOOGLE_CLIENT_ID,
    client_secret: c.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: `${new URL(c.req.url).origin}/auth/google/callback`,
  })

  return middleware(c, next)
})

/**
 * Google OAuth callback
 */
router.get('/callback', rateLimiter, async (c, next) => {
  const middleware = googleAuth({
    scope: ['email', 'profile'],
    client_id: c.env.GOOGLE_CLIENT_ID,
    client_secret: c.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: `${new URL(c.req.url).origin}/auth/google/callback`,
  })

  await middleware(c, next)

  const googleUser = c.get('user-google')
  if (
    !googleUser ||
    !googleUser.id ||
    !googleUser.email ||
    !googleUser.verified_email ||
    !googleUser.name ||
    !googleUser.given_name ||
    !googleUser.family_name
  ) {
    throw new Error('Incomplete Google user data received')
  }

  const db = createDB(c.env)

  const { user, token, session } = await handleGoogleAuth(
    db,
    c.env.KV,
    c.env,
    {
      id: googleUser.id,
      email: googleUser.email,
      verified_email: googleUser.verified_email,
      name: googleUser.name,
      given_name: googleUser.given_name,
      family_name: googleUser.family_name,
      picture: googleUser.picture || '',
      locale: googleUser.locale || 'en',
    },
    {
      userAgent: c.req.header('User-Agent'),
      ipAddress: c.req.header('CF-Connecting-IP'),
    }
  )

  const csrfToken = generateCsrfToken()

  setCookie(c, SESSION_COOKIE, session.id, {
    ...COOKIE_OPTIONS,
    maxAge: 7 * 24 * 60 * 60,
  })

  setCookie(c, CSRF_COOKIE, csrfToken, COOKIE_OPTIONS)

  return c.json({
    user,
    token: {
      accessToken: token.accessToken,
      expiresIn: token.expiresIn,
    },
    csrfToken,
  })
})

export default router
