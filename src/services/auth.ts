import { eq } from 'drizzle-orm'
import { ErrorCodes, ErrorMessages } from '../constants/error'
import { MAX_SESSIONS_PER_USER, SESSION_EXPIRY } from '../constants/services'
import { createDB } from '../db'
import * as schema from '../db/schema'
import { createError } from '../lib/error'
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
import { HttpStatusCode } from '../types/http'
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
  try {
    const drizzleDB = createDB({ DB: db } as CloudflareBindings)

    const existingUser = await drizzleDB
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, data.email))
      .get()

    if (existingUser) {
      throw createError(ErrorCodes.CONFLICT, HttpStatusCode.CONFLICT, 'Email already registered')
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
  } catch (error) {
    console.error('Actual error:', error)
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Registration failed',
      { error }
    )
  }
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
  try {
    const drizzleDB = createDB({ DB: db } as CloudflareBindings)

    const user = await drizzleDB
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, data.email))
      .get()

    if (!user || !user.password) {
      throw createError(
        ErrorCodes.INVALID_REQUEST,
        HttpStatusCode.UNAUTHORIZED,
        'Invalid credentials'
      )
    }

    if (!user.emailVerified) {
      throw createError(
        ErrorCodes.EMAIL_NOT_VERIFIED,
        HttpStatusCode.UNAUTHORIZED,
        ErrorMessages[ErrorCodes.EMAIL_NOT_VERIFIED]
      )
    }

    const isValid = await verifyPassword(data.password, user.password)
    if (!isValid) {
      throw createError(
        ErrorCodes.INVALID_REQUEST,
        HttpStatusCode.UNAUTHORIZED,
        'Invalid credentials'
      )
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
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Login failed',
      { error }
    )
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
  try {
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

    await kv.put(`session:${userId}:${session.id}`, JSON.stringify(session), {
      expirationTtl: SESSION_EXPIRY,
    })

    return SessionSchema.parse(session)
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Failed to create session',
      { error }
    )
  }
}

/**
 * Validate session
 */
export const validateSession = async (
  kv: KVNamespace,
  sessionId: string,
  userId: string
): Promise<Session | null> => {
  try {
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
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Session validation failed',
      { error }
    )
  }
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
  try {
    await kv.delete(`session:${userId}:${sessionId}`)

    await blacklistToken(jti, exp, kv)
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Logout failed',
      { error }
    )
  }
}

/**
 * Get user by ID
 */
export const getUserById = async (db: D1Database, userId: string): Promise<User | null> => {
  try {
    const drizzleDB = createDB({ DB: db } as CloudflareBindings)

    const user = await drizzleDB
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .get()

    if (!user) {
      return null
    }

    const { password: _, ...userWithoutPassword } = user
    return UserSchema.parse({
      ...userWithoutPassword,
      role: UserRoleEnum.USER,
      provider: AuthProviderEnum.EMAIL,
      emailVerified: false,
    })
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Failed to get user',
      { error }
    )
  }
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
  try {
    const storedToken = await kv.get(`refresh:${userId}:${refreshToken}`)
    if (!storedToken) {
      throw createError(
        ErrorCodes.INVALID_TOKEN,
        HttpStatusCode.UNAUTHORIZED,
        'Invalid refresh token'
      )
    }

    const user = await getUserById(db, userId)
    if (!user) {
      throw createError(ErrorCodes.USER_NOT_FOUND, HttpStatusCode.NOT_FOUND, 'User not found')
    }

    const tokenPayload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'> = {
      sub: user.id,
      email: user.email,
      role: UserRoleEnum.USER,
    }

    return await generateAuthTokens(tokenPayload, privateKey)
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Token refresh failed',
      { error }
    )
  }
}
