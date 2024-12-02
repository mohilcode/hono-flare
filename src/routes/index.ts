import type { Hono } from 'hono'
import userRoutes from './users'

export const registerRoutes = (app: Hono<{ Bindings: CloudflareBindings }>) => {
  app.route('/users', userRoutes)
}
