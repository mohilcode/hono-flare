export const isDevelopment = (env: CloudflareBindings) => env.ENV === 'development'
export const isProduction = (env: CloudflareBindings) => env.ENV === 'production'
