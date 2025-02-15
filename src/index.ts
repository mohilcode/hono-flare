import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { prettyJSON } from 'hono/pretty-json'
import { secureHeaders } from 'hono/secure-headers'
import { requestId } from 'hono/request-id'
import type { RequestIdVariables } from 'hono/request-id'
import { isDevelopment, isProduction, LOCALHOST, PRODUCTION } from './constants/env'
import { errorHandler } from './middleware/error'
import { registerRoutes } from './routes'
import { ResourceNotFoundError } from './types/error'

const app = new Hono<{
  Bindings: CloudflareBindings
  Variables: RequestIdVariables
}>()

app.use('*', logger())
app.use('*', requestId())

app.use('*', async (c, next) => {
  return cors({
    origin: isProduction ? PRODUCTION : LOCALHOST,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: [
      'Content-Type',
      'Authorization',
      'X-CSRF-Token'
    ],
    credentials: true,
    maxAge: 86400
  })(c, next)
})

app.use('*', async (c, next) => {
  if (isDevelopment) {
    return prettyJSON()(c, next)
  }
  await next()
})

app.get('/health', c =>
  c.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV,
  })
)

app.use('*', (c, next) => {
  return secureHeaders({
    strictTransportSecurity: isDevelopment
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
