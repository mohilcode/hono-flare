import type { Hono } from 'hono'
import authRoutes from './auth'
import type { BaseEnv } from '../types/hono'

export const registerRoutes = (
  app: Hono<BaseEnv>
) => {
  app.route('/auth', authRoutes)
}
