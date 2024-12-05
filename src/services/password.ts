import { eq } from 'drizzle-orm'
import { ErrorCodes } from '../constants/error'
import { EMAIL_FROM, RESET_TOKEN_PREFIX, RESET_TOKEN_EXPIRY } from '../constants/services'
import {
  createPasswordResetEmailTemplate,
  createPasswordResetSuccessfulTemplate,
} from '../constants/templates'
import { createDB } from '../db'
import * as schema from '../db/schema'
import { createError } from '../lib/error'
import { createEmailConfig } from '../services/email'
import type { ForgotPasswordRequest, ResetPasswordRequest } from '../types/auth'
import type { HttpStatus } from '../types/http'
import { generateId, hashPassword } from '../utils/crypto'

export const generateResetToken = async (
  kv: KVNamespace,
  userId: string,
  email: string
): Promise<string> => {
  const token = generateId()

  await kv.put(`${RESET_TOKEN_PREFIX}${token}`, JSON.stringify({ userId, email }), {
    expirationTtl: RESET_TOKEN_EXPIRY,
  })

  return token
}

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

export const validateResetToken = async (
  kv: KVNamespace,
  token: string
): Promise<{ userId: string; email: string } | null> => {
  const data = await kv.get(`${RESET_TOKEN_PREFIX}${token}`)
  if (!data) {
    return null
  }

  return JSON.parse(data)
}

export const resetPassword = async (
  db: D1Database,
  kv: KVNamespace,
  { token, password }: ResetPasswordRequest,
  resendApiKey: string
): Promise<void> => {
  const tokenData = await validateResetToken(kv, token)

  if (!tokenData) {
    throw createError(ErrorCodes.INVALID_TOKEN, 400 as HttpStatus, 'Invalid or expired reset token')
  }

  const drizzleDB = createDB({ DB: db } as CloudflareBindings)
  const passwordHash = await hashPassword(password)

  await drizzleDB
    .update(schema.users)
    .set({
      password: passwordHash,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, tokenData.userId))
    .run()

  await kv.delete(`${RESET_TOKEN_PREFIX}${token}`)

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
