import { PRODUCTION, isProduction } from '../constants/env'

export const RESEND_API_URL = 'https://api.resend.com'

export const CSRF_HEADER = 'X-CSRF-Token'
export const PBKDF2_ITERATIONS = 100000
export const SALT_LENGTH = 16
export const KEY_LENGTH = 32

export const RATE_LIMIT_PREFIX = 'rate_limit:email_verify:'
export const RATE_LIMIT_PASSWORD_RESET = 'reset_limit:'
export const RATE_LIMIT_WINDOW = 60 * 60
export const RATE_LIMIT_MAX = 5

export const SESSION_COOKIE = 'session-id'
export const CSRF_COOKIE = 'csrf-token'
export const REFRESH_COOKIE = 'refresh-token'
export const ACCESS_TOKEN_COOKIE = 'access-token'
export const SESSION_EXPIRY = 7 * 24 * 60 * 60
export const MAX_SESSIONS_PER_USER = 5

export const TOKEN_PREFIX = 'email_verify:'
export const TOKEN_EXPIRY = 24 * 60 * 60
export const TOKEN_LENGTH = 32
export const RESET_TOKEN_PREFIX = 'pwd_reset:'
export const RESET_TOKEN_EXPIRY = 60 * 60
export const ACCESS_TOKEN_EXPIRY = 15 * 60

export const EMAIL_FROM = 'Upresume <mohil@account.upresume.io>'

const DOMAIN = new URL(PRODUCTION).hostname

export const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProduction,
  sameSite: 'Lax' as const,
  path: '/',
  domain: isProduction ? DOMAIN : undefined,
}
