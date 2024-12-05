import { z } from 'zod'

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
  role: z.enum([UserRoleEnum.USER, UserRoleEnum.ADMIN]).default(UserRoleEnum.USER),
  provider: z
    .enum([AuthProviderEnum.EMAIL, AuthProviderEnum.GOOGLE])
    .default(AuthProviderEnum.EMAIL),
  providerId: z.string().optional(),
  emailVerified: z.boolean().default(false),
  createdAt: z.date(),
  updatedAt: z.date(),
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

export const JWTPayloadSchema = z.object({
  sub: z.string(),
  email: z.string().email(),
  role: z.enum([UserRoleEnum.USER, UserRoleEnum.ADMIN]),
  iat: z.number(),
  exp: z.number(),
  jti: z.string(),
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

export type User = z.infer<typeof UserSchema>
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>
export type LoginRequest = z.infer<typeof LoginRequestSchema>
export type JWTPayload = z.infer<typeof JWTPayloadSchema>
export type Session = z.infer<typeof SessionSchema>
export type Token = z.infer<typeof TokenSchema>

export type AuthError = {
  code: string
  message: string
  status: number
}

export type AuthKVNamespace = {
  sessions: KVNamespace
  tokens: KVNamespace
}

export interface VerificationToken {
  token: string
  userId: string
  email: string
  createdAt: number
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

export type Variables = {
  jwtPayload: JWTPayload
  userId: string
  sessionId: string
}

export interface ForgotPasswordRequest {
  email: string
}

export interface ResetPasswordRequest {
  token: string
  password: string
}

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
