import { eq } from 'drizzle-orm'
import { MAX_SESSIONS_PER_USER, SESSION_EXPIRY } from '../constants/services'
import { createDB } from '../db'
import * as schema from '../db/schema'
import { createEmailConfig } from '../services/email'
import { createVerificationToken } from '../services/verification'
import {
  AuthProviderEnum,
  type JWTPayload,
  type LoginRequest,
  type RegisterRequest,
  type Session,
  SessionSchema,
  type Token,
  type User,
  UserRoleEnum,
  UserSchema,
} from '../types/auth'
import { AuthenticationError, ConflictError, ResourceNotFoundError } from '../types/error'
import { generateId, hashPassword, verifyPassword } from '../utils/crypto'
import { blacklistToken, generateAuthTokens } from '../utils/jwt'

/**
 * Create a new user account
 */
export const registerUser = async (
  db: D1Database,
  kv: KVNamespace,
  data: RegisterRequest,
  baseUrl: string,
  emailApiKey: string
): Promise<User> => {
  const drizzleDB = createDB({ DB: db } as CloudflareBindings)

  const existingUser = await drizzleDB
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, data.email))
    .get()

  if (existingUser) {
    throw new ConflictError('Email already registered')
  }

  const passwordHash = await hashPassword(data.password)
  const now = new Date()
  const userId = generateId()

  const newUser = {
    id: userId,
    email: data.email,
    firstName: data.firstName,
    lastName: data.lastName,
    password: passwordHash,
    createdAt: now,
    updatedAt: now,
    googleId: null,
  }

  await drizzleDB.insert(schema.users).values(newUser)

  const { verificationUrl } = await createVerificationToken(kv, userId, data.email, baseUrl)

  const emailConfig = createEmailConfig(emailApiKey)
  await emailConfig.sendVerificationEmail({
    to: data.email,
    firstName: data.firstName,
    verificationUrl,
  })

  const { password: _, ...userWithoutPassword } = newUser
  return UserSchema.parse({
    ...userWithoutPassword,
    role: UserRoleEnum.USER,
    provider: AuthProviderEnum.EMAIL,
    emailVerified: false,
  })
}

/**
 * Authenticate user and create session
 */
export const loginUser = async (
  db: D1Database,
  kv: KVNamespace,
  data: LoginRequest,
  privateKey: CryptoKey,
  userAgent?: string,
  ipAddress?: string
): Promise<{ user: User; token: Token; session: Session }> => {
  const drizzleDB = createDB({ DB: db } as CloudflareBindings)

  const user = await drizzleDB
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, data.email))
    .get()

  if (!user || !user.password) {
    throw new AuthenticationError('Invalid credentials')
  }

  if (!user.emailVerified) {
    throw new AuthenticationError('Please verify your email address before logging in')
  }

  const isValid = await verifyPassword(data.password, user.password)
  if (!isValid) {
    throw new AuthenticationError('Invalid credentials')
  }

  const session = await createSession(kv, user.id, userAgent, ipAddress)

  const tokenPayload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'> = {
    sub: user.id,
    email: user.email,
    role: UserRoleEnum.USER,
  }

  const token = await generateAuthTokens(tokenPayload, privateKey)

  const { password: _, ...userWithoutPassword } = user
  return {
    user: UserSchema.parse({
      ...userWithoutPassword,
      role: UserRoleEnum.USER,
      provider: AuthProviderEnum.EMAIL,
      emailVerified: true,
    }),
    token,
    session,
  }
}

/**
 * Create a new session
 */
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

/**
 * Validate session
 */
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

/**
 * Logout user and invalidate session
 */
export const logoutUser = async (
  kv: KVNamespace,
  sessionId: string,
  userId: string,
  jti: string,
  exp: number
): Promise<void> => {
  await kv.delete(`session:${userId}:${sessionId}`)

  await blacklistToken(jti, exp, kv)
}

/**
 * Get user by ID
 */
export const getUserById = async (db: D1Database, userId: string): Promise<User | null> => {
  const drizzleDB = createDB({ DB: db } as CloudflareBindings)

  const user = await drizzleDB.select().from(schema.users).where(eq(schema.users.id, userId)).get()

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

/**
 * Validate refresh token and create new access token
 */
export const refreshAccessToken = async (
  db: D1Database,
  kv: KVNamespace,
  refreshToken: string,
  userId: string,
  privateKey: CryptoKey
): Promise<Token> => {
  const storedToken = await kv.get(`refresh:${userId}:${refreshToken}`)
  if (!storedToken) {
    throw new AuthenticationError('Invalid refresh token')
  }

  const user = await getUserById(db, userId)
  if (!user) {
    throw new ResourceNotFoundError('User not found')
  }

  const tokenPayload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'> = {
    sub: user.id,
    email: user.email,
    role: UserRoleEnum.USER,
  }

  return await generateAuthTokens(tokenPayload, privateKey)
}

/**
 * Get all active sessions for a user
 */
export const getUserSessions = async (kv: KVNamespace, userId: string): Promise<Session[]> => {
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

/**
 * Revoke all sessions for a user except the current one
 */
export const revokeOtherSessions = async (
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
