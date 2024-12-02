import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { prettyJSON } from 'hono/pretty-json'
import { isDevelopment } from './constants/env'
import { ErrorCodes, ErrorMessages } from './constants/error'
import { errorHandler } from './middleware/error'
import { registerRoutes } from './routes'

const app = new Hono<{ Bindings: CloudflareBindings }>()

app.use('*', logger())
app.use('*', cors())

app.use('*', async (c, next) => {
  if (isDevelopment(c.env)) {
    return prettyJSON()(c, next)
  }
  await next()
})

app.get('/health', c =>
  c.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    env: c.env.ENV,
  })
)

registerRoutes(app)

app.onError(errorHandler)

app.notFound(c => {
  return c.json(
    {
      code: ErrorCodes.RESOURCE_NOT_FOUND,
      message: ErrorMessages[ErrorCodes.RESOURCE_NOT_FOUND],
    },
    { status: 404 }
  )
})

export default app
