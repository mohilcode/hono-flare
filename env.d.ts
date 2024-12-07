interface CloudflareBindings {
  ENV: 'development' | 'production'
  DB: D1Database
  CLOUDFLARE_ACCOUNT_ID: string
  CLOUDFLARE_DATABASE_ID: string
  CLOUDFLARE_D1_TOKEN: string
  KV: KVNamespace
  R2: R2Bucket
  RESEND_API_KEY: string
  GOOGLE_CLIENT_ID: string
  GOOGLE_CLIENT_SECRET: string
}
