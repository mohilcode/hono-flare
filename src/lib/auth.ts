import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'
import { admin } from 'better-auth/plugins'
import { API_BASE_URL, FRONTEND_LOCALHOST, PRODUCTION } from '../constants/env'
import { EMAIL_FROM } from '../constants/services'
import { createDB } from '../db'
import { sendEmail } from './email'

export const getAuth = (env: CloudflareBindings) => {
  const db = createDB(env)
  return betterAuth({
    database: drizzleAdapter(db, {
      provider: 'sqlite',
    }),
    trustedOrigins: [FRONTEND_LOCALHOST, PRODUCTION],
    secondaryStorage: {
      get: async key => {
        const value = await env.KV.get(key)
        return value ? value.toString() : null
      },
      set: async (key, value, ttl) => {
        if (ttl) {
          await env.KV.put(key, value, { expirationTtl: ttl })
        } else {
          await env.KV.put(key, value)
        }
      },
      delete: async key => {
        await env.KV.delete(key)
      },
    },
    plugins: [admin()],
    emailAndPassword: {
      enabled: true,
      autoSignIn: false,
      requireEmailVerification: true,
      sendResetPassword: async ({ user, token }) => {
        const resetPasswordUrl = `${API_BASE_URL}/api/auth/reset-password?token=${token}`
        await sendEmail(
          {
            from: EMAIL_FROM,
            to: user.email,
            subject: 'Reset your password',
            html: `<p>Click <a href="${resetPasswordUrl}">here</a> to reset your password.</p>`,
          },
          env.RESEND_API_KEY
        )
      },
    },
    emailVerification: {
      sendOnSignUp: true,
      sendVerificationEmail: async ({ user, token }) => {
        const verificationUrl = `${API_BASE_URL}/api/auth/verify-email?token=${token}`
        await sendEmail(
          {
            from: EMAIL_FROM,
            to: user.email,
            subject: 'Verify your email',
            html: `<p>Click <a href="${verificationUrl}">here</a> to verify your email address.</p>`,
          },
          env.RESEND_API_KEY
        )
      },
    },
    socialProviders: {
      google: {
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
      },
    },
  })
}
