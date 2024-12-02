export type HttpStatus =
  | 200
  | 201
  | 204
  | 400
  | 401
  | 403
  | 404
  | 405
  | 409
  | 422
  | 429
  | 500
  | 502
  | 503

export const HttpStatusCode = {
  OK: 200 as const,
  CREATED: 201 as const,
  NO_CONTENT: 204 as const,
  BAD_REQUEST: 400 as const,
  UNAUTHORIZED: 401 as const,
  FORBIDDEN: 403 as const,
  NOT_FOUND: 404 as const,
  METHOD_NOT_ALLOWED: 405 as const,
  CONFLICT: 409 as const,
  UNPROCESSABLE_ENTITY: 422 as const,
  TOO_MANY_REQUESTS: 429 as const,
  INTERNAL_SERVER_ERROR: 500 as const,
  BAD_GATEWAY: 502 as const,
  SERVICE_UNAVAILABLE: 503 as const,
} as const
