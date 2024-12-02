import type { ErrorCodes } from '../constants/error'
import { ErrorMessages } from '../constants/error'
import type { HttpStatus } from '../types/http'

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes]

export class APIError extends Error {
  constructor(
    public readonly code: ErrorCode,
    public readonly statusCode: HttpStatus,
    message: string,
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    public readonly details?: Record<string, any>
  ) {
    super(message)
    this.name = this.constructor.name
  }
}

export const createError = (
  code: ErrorCode,
  statusCode: HttpStatus,
  message?: string,
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  details?: Record<string, any>
) => {
  return new APIError(code, statusCode, message ?? ErrorMessages[code], details)
}
