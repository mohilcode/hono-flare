import type { RequestIdVariables } from 'hono/request-id'
import type { auth } from '../lib/auth'

export interface BaseEnv {
  Bindings: CloudflareBindings
  Variables: RequestIdVariables & {
    user: typeof auth.$Infer.Session.user | null
    session: typeof auth.$Infer.Session.session | null
  }
}
