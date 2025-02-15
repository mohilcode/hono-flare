export const LOCALHOST = 'http://localhost:3000'
export const PRODUCTION = 'https://mohil.dev'

export const NODE_ENV = process.env.NODE_ENV || 'development'
export const isDevelopment = NODE_ENV === 'development'
export const isProduction = NODE_ENV === 'production'