import fs from 'node:fs'
import path from 'node:path'
import dotenv from 'dotenv'
import { defineConfig } from 'drizzle-kit'

dotenv.config({ path: '.dev.vars' })

const { CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_DATABASE_ID, CLOUDFLARE_D1_TOKEN } = process.env

const getLocalD1DB = (): string => {
  try {
    const d1Path = path.resolve('.wrangler/state/v3/d1/miniflare-D1DatabaseObject')

    if (!fs.existsSync(d1Path)) {
      throw new Error('D1 directory not found. Run db:init:local first.')
    }

    const files = fs.readdirSync(d1Path)
    const dbFile = files.find(f => f.endsWith('.sqlite'))

    if (!dbFile) {
      throw new Error('No SQLite file found in D1 directory. Run db:init:local first.')
    }

    return path.resolve(d1Path, dbFile)
  } catch (err) {
    throw new Error(`Failed to find local D1 database: ${err}`)
  }
}

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle/migrations',
  dialect: 'sqlite',
  ...(process.env.REMOTE === 'true'
    ? {
        driver: 'd1-http',
        dbCredentials: {
          accountId: CLOUDFLARE_ACCOUNT_ID || '',
          databaseId: CLOUDFLARE_DATABASE_ID || '',
          token: CLOUDFLARE_D1_TOKEN || '',
        },
      }
    : {
        dbCredentials: {
          url: getLocalD1DB(),
        },
      }),
})
