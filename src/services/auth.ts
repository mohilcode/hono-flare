import { eq } from 'drizzle-orm'
import { MAX_SESSIONS_PER_USER, RATE_LIMIT_MAX, SESSION_EXPIRY } from '../constants/services'
import type { DBType } from '../db'
import * as schema from '../db/schema'
import {
  createEmailConfig,
  getEmailDomain,
  isDisposableEmail,
  validateEmail,
} from '../services/email'
import { checkRateLimit, createVerificationToken, verifyToken } from '../services/verification'
import {
  AuthProviderEnum,
  type GetCurrentSessionParams,
  type JWTPayload,
  type LoginResponse,
  type LoginUserParams,
  type LogoutUserParams,
  type RefreshTokenParams,
  type RegisterUserParams,
  type ResendVerificationEmailParams,
  type Session,
  type SessionInfo,
  SessionSchema,
  type Token,
  type User,
  UserRoleEnum,
  UserSchema,
  type VerifyEmailTokenParams,
} from '../types/auth'
import {
  AuthenticationError,
  ConflictError,
  RateLimitError,
  ResourceNotFoundError,
  ValidationError,
} from '../types/error'
import { generateCsrfToken, generateId, hashPassword, verifyPassword } from '../utils/crypto'
import {
  blacklistToken,
  generateAuthTokens,
  isTokenBlacklisted,
  verifyJWTToken,
} from '../utils/jwt'

const _getUserById = async (db: DBType, userId: string): Promise<User | null> => {
  const user = await db.select().from(schema.users).where(eq(schema.users.id, userId)).get()

  if (!user) {
    return null
  }

  const { password: _, ...userWithoutPassword } = user
  return UserSchema.parse({
    ...userWithoutPassword,
    role: UserRoleEnum.USER,
    provider: AuthProviderEnum.EMAIL,
    emailVerified: user.emailVerified,
  })
}

export const registerUser = async ({
  db,
  kv,
  userData,
  baseUrl,
  resendApiKey,
}: RegisterUserParams): Promise<void> => {
  const existingUser = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, userData.email))
    .get()

  if (existingUser) {
    throw new ConflictError('Email already registered')
  }

  const domain = getEmailDomain(userData.email)
  if (await isDisposableEmail(domain)) {
    throw new ValidationError('Disposable email addresses are not allowed')
  }

  const passwordHash = await hashPassword(userData.password)
  const now = new Date()
  const userId = generateId()

  const newUser = {
    id: userId,
    email: userData.email,
    firstName: userData.firstName,
    lastName: userData.lastName,
    password: passwordHash,
    createdAt: now,
    updatedAt: now,
    googleId: null,
  }

  await db.insert(schema.users).values(newUser)

  const { verificationUrl } = await createVerificationToken(kv, userId, userData.email, baseUrl)

  const emailConfig = createEmailConfig(resendApiKey)
  await emailConfig.sendVerificationEmail({
    to: userData.email,
    firstName: userData.firstName,
    verificationUrl,
  })
}

export const loginUser = async ({
  db,
  kv,
  env,
  loginData,
  userAgent,
  ipAddress,
}: LoginUserParams): Promise<LoginResponse> => {
  const user = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, loginData.email))
    .get()

  if (!user || !user.password) {
    throw new AuthenticationError('Invalid credentials')
  }

  if (!user.emailVerified) {
    throw new AuthenticationError('Please verify your email address before logging in')
  }

  const isValid = await verifyPassword(loginData.password, user.password)
  if (!isValid) {
    throw new AuthenticationError('Invalid credentials')
  }

  const tokenPayload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'> = {
    sub: user.id,
    email: user.email,
    role: UserRoleEnum.USER,
  }

  const token = await generateAuthTokens(tokenPayload, env)
  const session = await createSession(kv, user.id, userAgent, ipAddress)
  const csrfToken = generateCsrfToken()

  return {
    token,
    session,
    csrfToken,
  }
}

export const createSession = async (
  kv: KVNamespace,
  userId: string,
  userAgent?: string,
  ipAddress?: string
): Promise<Session> => {
  const existingSessions = await kv.list({ prefix: `session:${userId}:` })

  if (existingSessions.keys.length >= MAX_SESSIONS_PER_USER) {
    const oldestSession = existingSessions.keys[0]
    await kv.delete(oldestSession.name)
  }

  const now = Math.floor(Date.now() / 1000)
  const session: Session = {
    id: generateId(),
    userId,
    userAgent,
    ipAddress,
    expiresAt: now + SESSION_EXPIRY,
    createdAt: now,
  }

  const validatedSession = SessionSchema.parse(session)

  await kv.put(`session:${userId}:${session.id}`, JSON.stringify(validatedSession), {
    expirationTtl: SESSION_EXPIRY,
  })

  return validatedSession
}

export const validateSession = async (
  kv: KVNamespace,
  sessionId: string,
  userId: string
): Promise<Session | null> => {
  const sessionData = await kv.get(`session:${userId}:${sessionId}`)
  if (!sessionData) {
    return null
  }

  const session = SessionSchema.parse(JSON.parse(sessionData))
  const now = Math.floor(Date.now() / 1000)

  if (session.expiresAt <= now) {
    await kv.delete(`session:${userId}:${sessionId}`)
    return null
  }

  return session
}

export const logoutUser = async ({
  kv,
  sessionId,
  userId,
  jti,
  exp,
}: LogoutUserParams): Promise<void> => {
  await kv.delete(`session:${userId}:${sessionId}`)

  await blacklistToken(jti, exp, kv)
}

export const refreshAccessToken = async ({
  db,
  kv,
  env,
  refreshToken,
}: RefreshTokenParams): Promise<Token> => {
  const payload = await verifyJWTToken(refreshToken, env)

  const isBlacklisted = await isTokenBlacklisted(payload.jti, kv)
  if (isBlacklisted) {
    throw new AuthenticationError('Token has been revoked')
  }

  const user = await _getUserById(db, payload.sub)
  if (!user) {
    throw new ResourceNotFoundError('User not found')
  }

  return await generateAuthTokens(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
    },
    env
  )
}

export const getCurrentSession = async ({
  jwtPayload,
  sessionId,
  userId,
}: GetCurrentSessionParams): Promise<SessionInfo> => {
  return {
    id: sessionId,
    userId,
    exp: jwtPayload.exp,
    iat: jwtPayload.iat,
    email: jwtPayload.email,
    role: jwtPayload.role,
  }
}

export const resendVerificationEmail = async ({
  db,
  kv,
  email,
  baseUrl,
  resendApiKey,
}: ResendVerificationEmailParams): Promise<void> => {
  const domain = getEmailDomain(email)
  if (await isDisposableEmail(domain)) {
    throw new ValidationError('Disposable email addresses are not allowed')
  }

  if (!validateEmail(email)) {
    throw new ValidationError('Invalid email format')
  }

  if (!(await checkRateLimit(kv, email))) {
    throw new RateLimitError('Too many verification attempts', {
      resetIn: '1 hour',
      maxAttempts: RATE_LIMIT_MAX,
    })
  }

  const user = await db.select().from(schema.users).where(eq(schema.users.email, email)).get()

  if (!user) {
    throw new ResourceNotFoundError('User not found')
  }

  if (user.emailVerified) {
    return
  }

  const { verificationUrl } = await createVerificationToken(kv, user.id, email, baseUrl)

  const emailConfig = createEmailConfig(resendApiKey)
  await emailConfig.sendVerificationEmail({
    to: email,
    firstName: user.firstName,
    verificationUrl,
  })
}

export const verifyEmailToken = async ({
  db,
  kv,
  token,
  resendApiKey,
}: VerifyEmailTokenParams): Promise<void> => {
  const result = await verifyToken(kv, token)

  if (!result.success) {
    throw new ValidationError(result.error || 'Invalid verification token')
  }

  if (!result.userId) {
    throw new ValidationError('Invalid verification token: missing user ID')
  }

  const updateResult = await db
    .update(schema.users)
    .set({
      emailVerified: true,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, result.userId))
    .run()

  if (!updateResult.success) {
    throw new ValidationError('Failed to verify email: user not found')
  }

  const user = await db.select().from(schema.users).where(eq(schema.users.id, result.userId)).get()

  if (user) {
    const emailConfig = createEmailConfig(resendApiKey)
    await emailConfig.sendWelcomeEmail({
      to: user.email,
      firstName: user.firstName,
    })
  }
}

export const _revokeOtherSessions = async (
  kv: KVNamespace,
  userId: string,
  currentSessionId: string
): Promise<void> => {
  const { keys } = await kv.list({ prefix: `session:${userId}:` })

  for (const key of keys) {
    if (!key.name.endsWith(currentSessionId)) {
      await kv.delete(key.name)
    }
  }
}

export const _getUserSessions = async (kv: KVNamespace, userId: string): Promise<Session[]> => {
  const sessions: Session[] = []
  const { keys } = await kv.list({ prefix: `session:${userId}:` })

  for (const key of keys) {
    const sessionData = await kv.get(key.name)
    if (sessionData) {
      const session = SessionSchema.parse(JSON.parse(sessionData))
      const now = Math.floor(Date.now() / 1000)

      if (session.expiresAt > now) {
        sessions.push(session)
      } else {
        await kv.delete(key.name)
      }
    }
  }

  return sessions
}
