import type { Context } from 'hono'
import { z } from 'zod'
import type { DBType } from '../db'

export const UserRoleEnum = {
  USER: 'user',
  ADMIN: 'admin',
} as const

export const AuthProviderEnum = {
  EMAIL: 'email',
  GOOGLE: 'google',
} as const

export const UserSchema = z.object({
  id: z.string().min(1),
  email: z.string().email(),
  firstName: z.string().min(1).max(50),
  lastName: z.string().min(1).max(50),
  passwordHash: z.string().optional(),
  googleId: z.string().nullable().optional(),
  role: z.enum([UserRoleEnum.USER, UserRoleEnum.ADMIN]).default(UserRoleEnum.USER),
  provider: z
    .enum([AuthProviderEnum.EMAIL, AuthProviderEnum.GOOGLE])
    .default(AuthProviderEnum.EMAIL),
  emailVerified: z.boolean().default(false),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export const SessionSchema = z.object({
  id: z.string(),
  userId: z.string(),
  userAgent: z.string().optional(),
  ipAddress: z.string().optional(),
  expiresAt: z.number(),
  createdAt: z.number(),
})

export const TokenSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string().optional(),
  expiresIn: z.number(),
})

export const RegisterRequestSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(8)
    .max(100)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
  firstName: z.string().min(1).max(50),
  lastName: z.string().min(1).max(50),
})

export const LoginRequestSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
})

export const ResendVerifyEmailRequestSchema = z.object({
  email: z.string().email(),
})

export const ForgotPasswordRequestSchema = z.object({
  email: z.string().email(),
})

export const ResetPasswordRequestSchema = z.object({
  token: z.string().min(1),
  password: z
    .string()
    .min(8)
    .max(100)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
})

export const JWTPayloadSchema = z.object({
  sub: z.string(),
  email: z.string().email(),
  role: z.enum([UserRoleEnum.USER, UserRoleEnum.ADMIN]),
  iat: z.number(),
  exp: z.number(),
  jti: z.string(),
})

export type User = z.infer<typeof UserSchema>
export type Session = z.infer<typeof SessionSchema>
export type Token = z.infer<typeof TokenSchema>

export type RegisterRequest = z.infer<typeof RegisterRequestSchema>
export type LoginRequest = z.infer<typeof LoginRequestSchema>
export type JWTPayload = z.infer<typeof JWTPayloadSchema>

export type AuthError = {
  code: string
  message: string
  status: number
}

export interface LoginResponse {
  user: User
  token: Token
  session: Session
  csrfToken: string
}

export type AuthKVNamespace = {
  sessions: KVNamespace
  tokens: KVNamespace
}

export interface VerificationTokenMetadata {
  attempts: number
  lastAttempt: number
  ipAddress?: string
  userAgent?: string
}

export interface VerificationToken {
  token: string
  userId: string
  email: string
  createdAt: number
  metadata: VerificationTokenMetadata
}

export interface VerificationResult {
  success: boolean
  userId?: string
  email?: string
  error?: string
}

export interface RateLimitInfo {
  remaining: number
  reset: number
  limit: number
}

export interface GoogleUser {
  id: string
  email: string
  verified_email: boolean
  name: string
  given_name: string
  family_name: string
  picture: string
  locale: string
}

export interface GoogleAuthResponse {
  user: GoogleUser
  token: {
    access_token: string
    expires_in: number
  }
  granted_scopes: string[]
}

export type Variables = {
  jwtPayload: JWTPayload
  userId: string
  sessionId: string
}

export interface AuthHonoContext extends Context {
  get(key: 'jwtPayload'): JWTPayload
  get(key: 'userId'): string
  get(key: 'sessionId'): string
  get(key: 'user'): { emailVerified: boolean } & Record<string, unknown>
  set(key: 'jwtPayload', value: JWTPayload): void
  set(key: 'userId', value: string): void
  set(key: 'sessionId', value: string): void
  set(key: 'user', value: { emailVerified: boolean } & Record<string, unknown>): void
}

export interface ResetTokenData {
  userId: string
  email: string
  createdAt: number
}

export interface AuthMetadata {
  userAgent?: string
  ipAddress?: string
}

export interface InitiatePasswordResetParams {
  db: DBType
  kv: KVNamespace
  email: string
  baseUrl: string
  resendApiKey: string
}

export interface ResetPasswordParams {
  db: DBType
  kv: KVNamespace
  token: string
  newPassword: string
  resendApiKey: string
}

export interface RegisterUserParams {
  db: DBType
  kv: KVNamespace
  userData: RegisterRequest
  baseUrl: string
  resendApiKey: string
}

export interface VerifyEmailTokenParams {
  db: DBType
  kv: KVNamespace
  token: string
  resendApiKey: string
}

export interface LoginUserParams {
  db: DBType
  kv: KVNamespace
  env: CloudflareBindings
  loginData: LoginRequest
  userAgent?: string
  ipAddress?: string
}

export interface LogoutUserParams {
  kv: KVNamespace
  sessionId: string
  userId: string
  jti: string
  exp: number
}

export interface RefreshTokenParams {
  db: DBType
  kv: KVNamespace
  env: CloudflareBindings
  refreshToken: string
}

export interface GetCurrentSessionParams {
  jwtPayload: JWTPayload
  sessionId: string
  userId: string
}

export interface SessionInfo {
  id: string
  userId: string
  exp: number
  iat: number
  email: string
  role: string
}

export interface ResendVerificationEmailParams {
  db: DBType
  kv: KVNamespace
  email: string
  baseUrl: string
  resendApiKey: string
}
