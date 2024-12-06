import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { prettyJSON } from 'hono/pretty-json'
import { secureHeaders } from 'hono/secure-headers'
import { isDevelopment } from './constants/env'
import { errorHandler, requestId } from './middleware/error'
import { registerRoutes } from './routes'
import { ResourceNotFoundError } from './types/error'

const app = new Hono<{ Bindings: CloudflareBindings }>()

app.use('*', logger())
app.use('*', requestId)
app.use('*', cors())

app.use('*', async (c, next) => {
  if (isDevelopment(c.env.ENV)) {
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

app.use('*', (c, next) => {
  return secureHeaders({
    strictTransportSecurity: isDevelopment(c.env.ENV)
      ? false
      : 'max-age=31536000; includeSubDomains; preload',
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://cdnjs.cloudflare.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https:', 'data:'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: true,
    originAgentCluster: true,
    referrerPolicy: 'strict-origin-when-cross-origin',
    xContentTypeOptions: true,
    xDnsPrefetchControl: true,
    xDownloadOptions: true,
    xFrameOptions: 'DENY',
    xPermittedCrossDomainPolicies: true,
    xXssProtection: '1; mode=block',
  })(c, next)
})

registerRoutes(app)

app.onError(errorHandler)

app.notFound(c => {
  throw new ResourceNotFoundError('The requested resource was not found', {
    path: c.req.path,
    method: c.req.method,
  })
})

export default app
