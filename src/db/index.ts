import { drizzle } from 'drizzle-orm/d1'
import { isDevelopment } from '../constants/env'
import { getDB } from '../lib/context'
import * as schema from './schema'

export const createDB = () => {
  return drizzle(getDB(), {
    schema,
    logger: isDevelopment,
  })
}
