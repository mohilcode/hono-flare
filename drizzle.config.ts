import fs from 'node:fs'
import path from 'node:path'
import dotenv from 'dotenv'
import { defineConfig } from 'drizzle-kit'

dotenv.config({ path: '.dev.vars' })

const getLocalD1DB = () => {
  try {
    const basePath = path.resolve('.wrangler')
    const dbFile = fs
      .readdirSync(basePath, { encoding: 'utf-8', recursive: true })
      .find(f => f.endsWith('.sqlite'))

    if (!dbFile) {
      throw new Error(`.sqlite file not found in ${basePath}`)
    }

    const url = path.resolve(basePath, dbFile)
    return url
  } catch (err) {
    console.info(`Error finding local DB: ${err}`)
    return null
  }
}

const isRemote = process.env.TARGET === 'production' || process.env.TARGET === 'staging'
const isProduction = process.env.TARGET === 'production'

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './migrations',
  dialect: 'sqlite',
  ...(isRemote
    ? {
        driver: 'd1-http',
        dbCredentials: {
          accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
          databaseId: isProduction
            ? process.env.CLOUDFLARE_DATABASE_ID
            : process.env.CLOUDFLARE_DATABASE_ID_STAGING,
          token: process.env.CLOUDFLARE_D1_TOKEN,
        },
      }
    : {
        dbCredentials: {
          url: getLocalD1DB(),
        },
      }),
})
