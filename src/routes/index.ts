import type { Hono } from 'hono'
import type { BaseEnv } from '../types/hono'
import authRoutes from './auth'

export const registerRoutes = (app: Hono<BaseEnv>) => {
  const api = app.basePath('/api')

  api.route('/auth', authRoutes)
}
