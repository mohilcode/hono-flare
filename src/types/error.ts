import { z } from 'zod'
import { ErrorCodes } from '../constants/error'
import { type HttpStatus, HttpStatusCode } from './http'

export interface ErrorResponse {
  code: ErrorCode
  message: string
  details?: Record<string, unknown>
  stack?: string
  requestId?: string
  timestamp: string
}

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes]

export const ErrorResponseSchema = z.object({
  code: z.enum([
    ErrorCodes.SERVER_ERROR,
    ErrorCodes.INVALID_TOKEN,
    ErrorCodes.USER_NOT_FOUND,
    ErrorCodes.VALIDATION_ERROR,
    ErrorCodes.RATE_LIMIT_EXCEEDED,
    ErrorCodes.INVALID_REQUEST,
    ErrorCodes.RESOURCE_NOT_FOUND,
    ErrorCodes.UNAUTHORIZED,
    ErrorCodes.FORBIDDEN,
    ErrorCodes.METHOD_NOT_ALLOWED,
    ErrorCodes.CONFLICT,
    ErrorCodes.TOO_MANY_REQUESTS,
    ErrorCodes.BAD_GATEWAY,
    ErrorCodes.SERVICE_UNAVAILABLE,
    ErrorCodes.EMAIL_NOT_VERIFIED,
  ] as const),
  message: z.string(),
  details: z.record(z.unknown()).optional(),
  stack: z.string().optional(),
  requestId: z.string().optional(),
  timestamp: z.string(),
})

export class BaseError extends Error {
  constructor(
    public readonly code: ErrorCode,
    public readonly statusCode: HttpStatus,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message)
    this.name = this.constructor.name
    Error.captureStackTrace(this, this.constructor)
  }

  toJSON(): ErrorResponse {
    return {
      code: this.code,
      message: this.message,
      details: this.details,
      timestamp: new Date().toISOString(),
      ...(process.env.NODE_ENV === 'development' && { stack: this.stack }),
    }
  }
}

export class ValidationError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.VALIDATION_ERROR, HttpStatusCode.BAD_REQUEST, message, details)
  }
}

export class AuthenticationError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.UNAUTHORIZED, HttpStatusCode.UNAUTHORIZED, message, details)
  }
}

export class AuthorizationError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.FORBIDDEN, HttpStatusCode.FORBIDDEN, message, details)
  }
}

export class RateLimitError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.RATE_LIMIT_EXCEEDED, HttpStatusCode.TOO_MANY_REQUESTS, message, details)
  }
}

export class ResourceNotFoundError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.RESOURCE_NOT_FOUND, HttpStatusCode.NOT_FOUND, message, details)
  }
}

export class ConflictError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.CONFLICT, HttpStatusCode.CONFLICT, message, details)
  }
}

export class InvalidRequestError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.INVALID_REQUEST, HttpStatusCode.BAD_REQUEST, message, details)
  }
}

export class MethodNotAllowedError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.METHOD_NOT_ALLOWED, HttpStatusCode.METHOD_NOT_ALLOWED, message, details)
  }
}

export class ServerError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCodes.SERVER_ERROR, HttpStatusCode.INTERNAL_SERVER_ERROR, message, details)
  }
}

export const createError = (
  code: ErrorCode,
  message: string,
  details?: Record<string, unknown>
): BaseError => {
  switch (code) {
    case ErrorCodes.VALIDATION_ERROR:
      return new ValidationError(message, details)
    case ErrorCodes.UNAUTHORIZED:
      return new AuthenticationError(message, details)
    case ErrorCodes.FORBIDDEN:
      return new AuthorizationError(message, details)
    case ErrorCodes.RATE_LIMIT_EXCEEDED:
      return new RateLimitError(message, details)
    case ErrorCodes.RESOURCE_NOT_FOUND:
      return new ResourceNotFoundError(message, details)
    case ErrorCodes.CONFLICT:
      return new ConflictError(message, details)
    case ErrorCodes.EMAIL_NOT_VERIFIED:
      return new AuthenticationError(message, details)
    case ErrorCodes.INVALID_TOKEN:
      return new AuthenticationError(message, details)
    case ErrorCodes.USER_NOT_FOUND:
      return new ResourceNotFoundError(message, details)
    case ErrorCodes.METHOD_NOT_ALLOWED:
      return new ValidationError(message, details)
    case ErrorCodes.BAD_GATEWAY:
      return new ServerError(message, details)
    case ErrorCodes.SERVICE_UNAVAILABLE:
      return new ServerError(message, details)
    case ErrorCodes.TOO_MANY_REQUESTS:
      return new RateLimitError(message, details)
    case ErrorCodes.INVALID_REQUEST:
      return new InvalidRequestError(message, details)
    default:
      return new ServerError(message, details)
  }
}

export const isBaseError = (error: unknown): error is BaseError => {
  return error instanceof BaseError
}

export const toErrorResponse = (error: unknown, requestId?: string): ErrorResponse => {
  if (isBaseError(error)) {
    return {
      ...error.toJSON(),
      requestId,
    }
  }

  if (error instanceof Error) {
    return {
      code: ErrorCodes.SERVER_ERROR,
      message: error.message || 'An unexpected error occurred',
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      timestamp: new Date().toISOString(),
    }
  }

  return {
    code: ErrorCodes.SERVER_ERROR,
    message: 'An unexpected error occurred',
    timestamp: new Date().toISOString(),
  }
}

export const validateOrThrow = <T>(schema: z.ZodSchema<T>, data: unknown): T => {
  try {
    return schema.parse(data)
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new ValidationError('Validation failed', {
        errors: error.errors,
      })
    }
    throw error
  }
}

export interface ErrorLogContext {
  timestamp: string
  path: string
  method: string
  message: string
  stack?: string
  requestId?: string
  errorCode?: string
  statusCode?: number
  details?: Record<string, unknown>
}
