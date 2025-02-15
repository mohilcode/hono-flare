import { eq } from 'drizzle-orm'
import type { DBType } from '../db'
import * as schema from '../db/schema'
import type { AuthMetadata, GoogleUser } from '../types/auth'
import { ConflictError } from '../types/error'
import { generateAuthTokens } from '../utils/jwt'
import { createSession } from './auth'

export const handleGoogleAuth = async (
  db: DBType,
  kv: KVNamespace,
  env: CloudflareBindings,
  googleUser: GoogleUser,
  metadata?: AuthMetadata
) => {
  let user = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.googleId, googleUser.id))
    .get()

  if (!user) {
    user = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, googleUser.email))
      .get()

    if (user) {
      if (user.provider === 'email') {
        const { keys } = await kv.list({ prefix: `session:${user.id}:` })
        for (const key of keys) {
          await kv.delete(key.name)
        }

        await db
          .update(schema.users)
          .set({
            googleId: googleUser.id,
            provider: 'google',
            emailVerified: true,
            picture: googleUser.picture,
            updatedAt: new Date(),
          })
          .where(eq(schema.users.id, user.id))
          .run()

        user = await db.select().from(schema.users).where(eq(schema.users.id, user.id)).get()

        if (!user) {
          throw new Error('User not found after update')
        }
      } else if (user.googleId && user.googleId !== googleUser.id) {
        throw new ConflictError('Email already exists with different Google account')
      }
    } else {
      const result = await db
        .insert(schema.users)
        .values({
          email: googleUser.email,
          firstName: googleUser.given_name,
          lastName: googleUser.family_name,
          googleId: googleUser.id,
          provider: 'google',
          emailVerified: true,
          picture: googleUser.picture,
        })
        .run()

      if (!result.success) {
        throw new Error('Failed to create user')
      }

      user = await db
        .select()
        .from(schema.users)
        .where(eq(schema.users.googleId, googleUser.id))
        .get()

      if (!user) {
        throw new Error('User not found after creation')
      }
    }
  }

  const session = await createSession(kv, user.id, metadata?.userAgent, metadata?.ipAddress)

  const token = await generateAuthTokens(
    {
      sub: user.id,
      email: user.email,
      role: 'user',
    },
    env
  )

  return { user, token, session }
}
