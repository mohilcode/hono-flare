import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'
import { admin } from 'better-auth/plugins'
import { EMAIL_FROM } from '../constants/services'
import { createDB } from '../db'
import { getBindings, getKV } from './context'
import { sendEmail } from './email'

export const auth = betterAuth({
  database: drizzleAdapter(createDB(), {
    provider: 'sqlite',
  }),

  secondaryStorage: {
    get: async key => {
      const value = await getKV().get(key)
      return value ? value.toString() : null
    },
    set: async (key, value, ttl) => {
      if (ttl) {
        await getKV().put(key, value, { expirationTtl: ttl })
      } else {
        await getKV().put(key, value)
      }
    },
    delete: async key => {
      await getKV().delete(key)
    },
  },

  plugins: [admin()],

  emailAndPassword: {
    enabled: true,
    autoSignIn: false,
    requireEmailVerification: true,
    sendResetPassword: async ({ user, url }) => {
      await sendEmail({
        from: EMAIL_FROM,
        to: user.email,
        subject: 'Reset your password',
        html: `<p>Click <a href="${url}">here</a> to reset your password.</p>`,
      })
    },
  },

  emailVerification: {
    sendOnSignUp: true,
    sendVerificationEmail: async ({ user, url }) => {
      await sendEmail({
        from: EMAIL_FROM,
        to: user.email,
        subject: 'Verify your email',
        html: `<p>Click <a href="${url}">here</a> to verify your email address.</p>`,
      })
    },
  },

  socialProviders: {
    google: {
      clientId: getBindings().GOOGLE_CLIENT_ID,
      clientSecret: getBindings().GOOGLE_CLIENT_SECRET,
    },
  },
})
