import type { RequestIdVariables } from 'hono/request-id'
import type { getAuth } from '../lib/auth'

export interface BaseEnv {
  Bindings: CloudflareBindings
  Variables: RequestIdVariables & {
    user: ReturnType<typeof getAuth>['$Infer']['Session']['user'] | null
    session: ReturnType<typeof getAuth>['$Infer']['Session']['session'] | null
  }
}
