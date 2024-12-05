import type { Hono } from 'hono'
import authRoutes from './auth'

export const registerRoutes = (app: Hono<{ Bindings: CloudflareBindings }>) => {
  app.route('/auth', authRoutes)
}
