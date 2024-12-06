export const ErrorCodes = {
  SERVER_ERROR: 'SERVER_ERROR',
  BAD_GATEWAY: 'BAD_GATEWAY',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',

  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_REQUEST: 'INVALID_REQUEST',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  METHOD_NOT_ALLOWED: 'METHOD_NOT_ALLOWED',
  CONFLICT: 'CONFLICT',

  INVALID_TOKEN: 'INVALID_TOKEN',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  USER_NOT_FOUND: 'USER_NOT_FOUND',

  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  TOO_MANY_REQUESTS: 'TOO_MANY_REQUESTS',
} as const

export const ErrorMessages = {
  [ErrorCodes.SERVER_ERROR]: 'An unexpected error occurred',
  [ErrorCodes.BAD_GATEWAY]: 'The server received an invalid response',
  [ErrorCodes.SERVICE_UNAVAILABLE]: 'The service is temporarily unavailable',

  [ErrorCodes.VALIDATION_ERROR]: 'The request data is invalid',
  [ErrorCodes.INVALID_REQUEST]: 'The request format is invalid',
  [ErrorCodes.UNAUTHORIZED]: 'Authentication is required',
  [ErrorCodes.FORBIDDEN]: 'You do not have permission to perform this action',
  [ErrorCodes.RESOURCE_NOT_FOUND]: 'The requested resource was not found',
  [ErrorCodes.METHOD_NOT_ALLOWED]: 'The HTTP method is not allowed for this endpoint',
  [ErrorCodes.CONFLICT]: 'The request conflicts with the current state',

  [ErrorCodes.INVALID_TOKEN]: 'The provided authentication token is invalid or expired',
  [ErrorCodes.EMAIL_NOT_VERIFIED]: 'Please verify your email address to continue',
  [ErrorCodes.USER_NOT_FOUND]: 'The specified user was not found',

  [ErrorCodes.RATE_LIMIT_EXCEEDED]: 'Too many requests, please try again later',
  [ErrorCodes.TOO_MANY_REQUESTS]: 'Request limit exceeded, please try again later',
} as const

export const ErrorCategories = {
  SERVER: 'SERVER',
  CLIENT: 'CLIENT',
  AUTH: 'AUTH',
  RATE_LIMIT: 'RATE_LIMIT',
} as const

export const DefaultErrors = {
  SERVER: {
    code: ErrorCodes.SERVER_ERROR,
    message: ErrorMessages[ErrorCodes.SERVER_ERROR],
  },
  VALIDATION: {
    code: ErrorCodes.VALIDATION_ERROR,
    message: ErrorMessages[ErrorCodes.VALIDATION_ERROR],
  },
  AUTH: {
    code: ErrorCodes.UNAUTHORIZED,
    message: ErrorMessages[ErrorCodes.UNAUTHORIZED],
  },
  FORBIDDEN: {
    code: ErrorCodes.FORBIDDEN,
    message: ErrorMessages[ErrorCodes.FORBIDDEN],
  },
  NOT_FOUND: {
    code: ErrorCodes.RESOURCE_NOT_FOUND,
    message: ErrorMessages[ErrorCodes.RESOURCE_NOT_FOUND],
  },
  RATE_LIMIT: {
    code: ErrorCodes.RATE_LIMIT_EXCEEDED,
    message: ErrorMessages[ErrorCodes.RATE_LIMIT_EXCEEDED],
  },
} as const
