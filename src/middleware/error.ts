import type { Context } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { isDevelopment } from '../constants/env'
import { ErrorCodes } from '../constants/error'
import { APIError } from '../lib/error'
import { HttpStatusCode } from '../types/http'

export const errorLogger = async (err: Error, c: Context) => {
  console.error({
    timestamp: new Date().toISOString(),
    path: c.req.path,
    method: c.req.method,
    message: err.message,
    stack: err.stack,
    requestId: c.get('requestId'),
  })
}

export const errorHandler = async (err: Error, c: Context) => {
  await errorLogger(err, c)

  if (err instanceof APIError) {
    return c.json(
      {
        code: err.code,
        message: err.message,
        ...(err.details && { details: err.details }),
        ...(isDevelopment(c.env) && { stack: err.stack }),
      },
      { status: err.statusCode }
    )
  }

  if (err instanceof HTTPException) {
    return c.json(
      {
        code: ErrorCodes.INVALID_REQUEST,
        message: err.message,
        ...(isDevelopment(c.env) && { stack: err.stack }),
      },
      { status: err.status }
    )
  }

  if (err.name === 'ValidationError') {
    return c.json(
      {
        code: ErrorCodes.VALIDATION_ERROR,
        message: 'Validation failed',
        details: err,
      },
      { status: HttpStatusCode.BAD_REQUEST }
    )
  }

  return c.json(
    {
      code: ErrorCodes.SERVER_ERROR,
      message: 'Internal Server Error',
      ...(isDevelopment(c.env) && { stack: err.stack }),
    },
    { status: HttpStatusCode.INTERNAL_SERVER_ERROR }
  )
}
