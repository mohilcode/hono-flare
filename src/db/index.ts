import { drizzle } from 'drizzle-orm/d1'
import type { DrizzleD1Database } from 'drizzle-orm/d1'
import { isDevelopment } from '../constants/env'
import * as schema from './schema'

export const createDB = (env: CloudflareBindings) => {
  return drizzle(env.DB, {
    schema,
    logger: isDevelopment(env.ENV),
  })
}

export type DBType = DrizzleD1Database<typeof schema>
