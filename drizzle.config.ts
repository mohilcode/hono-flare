import dotenv from 'dotenv'
import { defineConfig } from 'drizzle-kit'

dotenv.config({ path: '.dev.vars' })

const {
  CLOUDFLARE_ACCOUNT_ID,
  CLOUDFLARE_DATABASE_ID,
  CLOUDFLARE_D1_TOKEN,
  CLOUDFLARE_DATABASE_ID_PREVIEW,
} = process.env

if (
  !CLOUDFLARE_ACCOUNT_ID ||
  !CLOUDFLARE_DATABASE_ID ||
  !CLOUDFLARE_D1_TOKEN ||
  !CLOUDFLARE_DATABASE_ID_PREVIEW
) {
  throw new Error('Missing required Cloudflare credentials')
}

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './migrations',
  dialect: 'sqlite',
  driver: 'd1-http',
  dbCredentials: {
    accountId: CLOUDFLARE_ACCOUNT_ID,
    databaseId:
      process.env.TARGET === 'prod' ? CLOUDFLARE_DATABASE_ID : CLOUDFLARE_DATABASE_ID_PREVIEW,
    token: CLOUDFLARE_D1_TOKEN,
  },
})
