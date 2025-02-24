export const NODE_ENV = process.env.NODE_ENV || 'development'
export const isDevelopment = NODE_ENV === 'development'
export const isProduction = NODE_ENV === 'production'

export const FRONTEND_LOCALHOST = 'http://localhost:8080'
export const BACKEND_LOCALHOST = 'http://localhost:3000'
export const PRODUCTION = 'https://mohil.dev'

export const APP_BASE_URL = isProduction ? PRODUCTION : FRONTEND_LOCALHOST
export const API_BASE_URL = isProduction ? PRODUCTION : BACKEND_LOCALHOST
