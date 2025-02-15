import type { Hono } from 'hono'
import type { RequestIdVariables } from 'hono/request-id'
import authRoutes from './auth'

export const registerRoutes = (app: Hono<{
  Bindings: CloudflareBindings
  Variables: RequestIdVariables
}>) => {
  app.route('/auth', authRoutes)
}