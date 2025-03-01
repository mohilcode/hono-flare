export const NODE_ENV = process.env.NODE_ENV || 'development'
export const isDevelopment = NODE_ENV === 'development'
export const isProduction = NODE_ENV === 'production'
export const isStaging = NODE_ENV === 'staging'

export const FRONTEND_LOCALHOST = 'http://localhost:8080'
export const STAGING_FRONTEND = 'https://staging.mohil.dev'
export const PRODUCTION_FRONTEND = 'https://mohil.dev'

export const BACKEND_LOCALHOST = 'http://localhost:3000'
export const STAGING_BACKEND = 'https://staging.mohil.dev'
export const PRODUCTION_BACKEND = 'https://mohil.dev'

export const APP_BASE_URL = isProduction
  ? PRODUCTION_FRONTEND
  : isStaging
    ? STAGING_FRONTEND
    : FRONTEND_LOCALHOST

export const API_BASE_URL = isProduction
  ? PRODUCTION_BACKEND
  : isStaging
    ? STAGING_BACKEND
    : BACKEND_LOCALHOST
