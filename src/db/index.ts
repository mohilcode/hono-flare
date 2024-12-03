import { drizzle } from 'drizzle-orm/d1'
import { isDevelopment } from '../constants/env'
import * as schema from './schema'

export const createDB = (env: CloudflareBindings) => {
  return drizzle(env.DB, {
    schema,
    logger: isDevelopment(env.ENV),
  })
}
