import { eq } from 'drizzle-orm'
import {
  EMAIL_FROM,
  RATE_LIMIT_PASSWORD_RESET,
  RESET_TOKEN_EXPIRY,
  RESET_TOKEN_PREFIX,
} from '../constants/services'
import type { DBType } from '../db'
import * as schema from '../db/schema'
import { createEmailConfig } from '../services/email'
import type {
  InitiatePasswordResetParams,
  ResetPasswordParams,
  ResetTokenData,
} from '../types/auth'
import {
  AuthenticationError,
  RateLimitError,
  ResourceNotFoundError,
  ValidationError,
} from '../types/error'
import { generateId, hashPassword } from '../utils/crypto'
import { verifyPassword } from '../utils/crypto'

const _checkResetRateLimit = async (kv: KVNamespace, email: string): Promise<boolean> => {
  const key = `${RATE_LIMIT_PASSWORD_RESET}${email}`
  const attempts = await kv.get(key)

  if (attempts && Number.parseInt(attempts) >= 3) {
    return false
  }

  const current = attempts ? Number.parseInt(attempts) : 0
  await kv.put(key, (current + 1).toString(), { expirationTtl: 3600 })

  return true
}

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

export const initiatePasswordReset = async ({
  db,
  kv,
  email,
  baseUrl,
  resendApiKey,
}: InitiatePasswordResetParams): Promise<void> => {
  const user = await db.select().from(schema.users).where(eq(schema.users.email, email)).get()

  if (!user) {
    return
  }

  if (!user.password) {
    throw new ValidationError('Account uses social login')
  }

  if (!(await _checkResetRateLimit(kv, email))) {
    throw new RateLimitError('Too many reset attempts', {
      resetIn: '1 hour',
      maxAttempts: 3,
    })
  }

  const token = await generateResetToken(kv, user.id, email)
  const resetUrl = `${baseUrl}/auth/reset-password?token=${token}`

  const emailConfig = createEmailConfig(resendApiKey)
  await emailConfig.sendInitiatePasswordEmail({
    to: email,
    firstName: user.firstName,
    resetUrl,
  })
}

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

export const resetPassword = async ({
  db,
  kv,
  token,
  newPassword,
  resendApiKey,
}: ResetPasswordParams): Promise<void> => {
  const tokenData = await validateResetToken(kv, token)

  const passwordHash = await hashPassword(newPassword)

  const result = await db
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

  const user = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.id, tokenData.userId))
    .get()

  if (user) {
    const emailConfig = createEmailConfig(resendApiKey)
    await emailConfig.sendPasswordResetEmail({
      to: user.email,
      firstName: user.firstName,
    })
  }
}

export const changePassword = async (
  db: DBType,
  kv: KVNamespace,
  userId: string,
  currentPassword: string,
  newPassword: string
): Promise<void> => {
  const user = await db.select().from(schema.users).where(eq(schema.users.id, userId)).get()

  if (!user || !user.password) {
    throw new ResourceNotFoundError('User not found')
  }

  const isValid = await verifyPassword(currentPassword, user.password)
  if (!isValid) {
    throw new AuthenticationError('Current password is incorrect')
  }

  const passwordHash = await hashPassword(newPassword)
  await db
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
