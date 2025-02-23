import { Hono } from 'hono'
import { auth } from '../lib/auth'
import type { BaseEnv } from '../types/hono'

const app = new Hono<BaseEnv>()

app.on(['POST', 'GET'], '/auth/*', c => {
  return auth.handler(c.req.raw)
})

export default app
