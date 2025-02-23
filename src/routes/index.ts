import type { Hono } from 'hono'
import type { BaseEnv } from '../types/hono'

export const registerRoutes = (app: Hono<BaseEnv>) => {
  const _api = app.basePath('/api')
}
