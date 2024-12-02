interface CloudflareBindings {
  ENV: 'development' | 'production'
  DB: D1Database
  CLOUDFLARE_ACCOUNT_ID: string
  CLOUDFLARE_DATABASE_ID: string
  CLOUDFLARE_D1_TOKEN: string
}
