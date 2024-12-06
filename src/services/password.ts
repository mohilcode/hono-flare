import { eq } from 'drizzle-orm'
import { EMAIL_FROM } from '../constants/services'
import {
  createPasswordResetEmailTemplate,
  createPasswordResetSuccessfulTemplate,
} from '../constants/templates'
import { createDB } from '../db'
import * as schema from '../db/schema'
import { createEmailConfig } from '../services/email'
import type { ForgotPasswordRequest, ResetPasswordRequest } from '../types/auth'
import { AuthenticationError, ResourceNotFoundError, ValidationError } from '../types/error'
import { generateId, hashPassword } from '../utils/crypto'
import { verifyPassword } from '../utils/crypto'

const RESET_TOKEN_EXPIRY = 60 * 60
const RESET_TOKEN_PREFIX = 'pwd_reset:'

interface ResetTokenData {
  userId: string
  email: string
  createdAt: number
}

/**
 * Generate password reset token and store in KV
 */
export const generateResetToken = async (
  kv: KVNamespace,
  userId: string,
  email: string
): Promise<string> => {
  const token = generateId()
  const tokenData: ResetTokenData = {
    userId,
    email,
    createdAt: Date.now(),
  }

  await kv.put(`${RESET_TOKEN_PREFIX}${token}`, JSON.stringify(tokenData), {
    expirationTtl: RESET_TOKEN_EXPIRY,
  })

  return token
}

/**
 * Initiate password reset process
 */
export const initiatePasswordReset = async (
  db: D1Database,
  kv: KVNamespace,
  { email }: ForgotPasswordRequest,
  baseUrl: string,
  resendApiKey: string
): Promise<void> => {
  const drizzleDB = createDB({ DB: db } as CloudflareBindings)

  const user = await drizzleDB
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, email))
    .get()

  if (!user) {
    return
  }

  if (!user.password) {
    throw new ValidationError('Account uses social login')
  }

  const token = await generateResetToken(kv, user.id, email)
  const resetUrl = `${baseUrl}/auth/reset-password?token=${token}`

  const emailConfig = createEmailConfig(resendApiKey)
  await emailConfig.sendEmail({
    from: EMAIL_FROM,
    to: email,
    subject: 'Password Reset Request',
    html: createPasswordResetEmailTemplate({
      firstName: user.firstName,
      resetUrl,
    }),
  })
}

/**
 * Validate password reset token
 */
export const validateResetToken = async (
  kv: KVNamespace,
  token: string
): Promise<ResetTokenData> => {
  const data = await kv.get(`${RESET_TOKEN_PREFIX}${token}`)
  if (!data) {
    throw new ValidationError('Invalid or expired reset token')
  }

  const tokenData = JSON.parse(data) as ResetTokenData

  const tokenAge = Date.now() - tokenData.createdAt
  if (tokenAge > RESET_TOKEN_EXPIRY * 1000) {
    await kv.delete(`${RESET_TOKEN_PREFIX}${token}`)
    throw new ValidationError('Reset token has expired')
  }

  return tokenData
}

/**
 * Complete password reset
 */
export const resetPassword = async (
  db: D1Database,
  kv: KVNamespace,
  { token, password }: ResetPasswordRequest,
  resendApiKey: string
): Promise<void> => {
  const tokenData = await validateResetToken(kv, token)
  const drizzleDB = createDB({ DB: db } as CloudflareBindings)

  const passwordHash = await hashPassword(password)

  const result = await drizzleDB
    .update(schema.users)
    .set({
      password: passwordHash,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, tokenData.userId))
    .run()

  if (!result.success) {
    throw new ResourceNotFoundError('User not found')
  }

  await kv.delete(`${RESET_TOKEN_PREFIX}${token}`)

  const { keys } = await kv.list({ prefix: `session:${tokenData.userId}:` })
  for (const key of keys) {
    await kv.delete(key.name)
  }

  const user = await drizzleDB
    .select()
    .from(schema.users)
    .where(eq(schema.users.id, tokenData.userId))
    .get()

  if (user) {
    const emailConfig = createEmailConfig(resendApiKey)
    await emailConfig.sendEmail({
      from: EMAIL_FROM,
      to: user.email,
      subject: 'Password Reset Successful',
      html: createPasswordResetSuccessfulTemplate(user.firstName),
    })
  }
}

/**
 * Change password for authenticated user
 */
export const changePassword = async (
  db: D1Database,
  kv: KVNamespace,
  userId: string,
  currentPassword: string,
  newPassword: string
): Promise<void> => {
  const drizzleDB = createDB({ DB: db } as CloudflareBindings)

  const user = await drizzleDB.select().from(schema.users).where(eq(schema.users.id, userId)).get()

  if (!user || !user.password) {
    throw new ResourceNotFoundError('User not found')
  }

  const isValid = await verifyPassword(currentPassword, user.password)
  if (!isValid) {
    throw new AuthenticationError('Current password is incorrect')
  }

  const passwordHash = await hashPassword(newPassword)
  await drizzleDB
    .update(schema.users)
    .set({
      password: passwordHash,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, userId))
    .run()

  const { keys } = await kv.list({ prefix: `session:${userId}:` })
  for (const key of keys) {
    await kv.delete(key.name)
  }
}

/**
 * Check password reset rate limit
 */
export const checkResetRateLimit = async (kv: KVNamespace, email: string): Promise<boolean> => {
  const key = `reset_limit:${email}`
  const attempts = await kv.get(key)

  if (attempts && Number.parseInt(attempts) >= 3) {
    return false
  }

  const current = attempts ? Number.parseInt(attempts) : 0
  await kv.put(key, (current + 1).toString(), { expirationTtl: 3600 })

  return true
}
