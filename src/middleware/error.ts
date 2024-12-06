import type { Context } from 'hono'
import { HTTPException } from 'hono/http-exception'
import type { z } from 'zod'
import { isDevelopment } from '../constants/env'
import { ErrorCodes } from '../constants/error'
import {
  type BaseError,
  type ErrorLogContext,
  type ErrorResponse,
  ValidationError,
  isBaseError,
  toErrorResponse,
} from '../types/error'
import { HttpStatusCode } from '../types/http'

export const errorLogger = async (err: Error | BaseError, c: Context): Promise<void> => {
  const logContext: ErrorLogContext = {
    timestamp: new Date().toISOString(),
    path: c.req.path,
    method: c.req.method,
    message: err.message,
    stack: err.stack,
    requestId: c.get('requestId'),
  }

  if (isBaseError(err)) {
    logContext.errorCode = err.code
    logContext.statusCode = err.statusCode
    logContext.details = err.details
  }

  console.error(logContext)
}

export const errorHandler = async (err: Error, c: Context) => {
  await errorLogger(err, c)

  let response: ErrorResponse
  let status: number

  if (isBaseError(err)) {
    response = err.toJSON()
    status = err.statusCode
  } else if (err instanceof HTTPException) {
    response = {
      code: ErrorCodes.INVALID_REQUEST,
      message: err.message,
      details: {
        status: err.status,
        name: err.name,
        ...(err.getResponse && { response: err.getResponse() }),
      },
      ...(isDevelopment(c.env.ENV) && { stack: err.stack }),
      timestamp: new Date().toISOString(),
    }
    status = err.status
  } else if (err instanceof Error && err.name === 'ZodError') {
    const zodError = err as z.ZodError
    const validationError = new ValidationError('Validation failed', {
      errors: zodError.errors.map(error => ({
        path: error.path,
        message: error.message,
        code: error.code,
      })),
    })
    response = validationError.toJSON()
    status = HttpStatusCode.BAD_REQUEST
  } else {
    response = toErrorResponse(err)
    status = HttpStatusCode.INTERNAL_SERVER_ERROR
  }

  if (isDevelopment(c.env.ENV)) {
    response.stack = err.stack
  }

  return c.json(response, { status })
}

export const requestId = async (c: Context, next: () => Promise<void>) => {
  const requestId = crypto.randomUUID()
  c.set('requestId', requestId)
  await next()
}
