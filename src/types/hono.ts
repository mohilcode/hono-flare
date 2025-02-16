import type { RequestIdVariables } from 'hono/request-id'
import type { JWTPayload } from './auth'

export interface BaseEnv {
  Bindings: CloudflareBindings
  Variables: RequestIdVariables
}

export interface AuthEnv extends BaseEnv {
  Variables: RequestIdVariables & {
    jwtPayload: JWTPayload
    userId: string
    sessionId: string
  }
}
