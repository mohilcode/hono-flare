# Cloudflare Workers with D1 and Drizzle

Development workflow for Cloudflare Workers Hono  projects using D1 database and Drizzle ORM.

## Quick Start

```bash
# Install dependencies
pnpm install

# Setup database
pnpm db:fresh     # Reset local DB and apply migrations
pnpm dev          # Start development server
```

## Database Management

```bash
# Local development
pnpm studio:local         # Open local DB UI
pnpm db:generate         # Generate new migrations
pnpm db:migrate:local    # Apply migrations locally

# Production
pnpm studio:remote       # Open production DB UI
pnpm db:migrate:prod     # Apply migrations to production
```

## Development Workflow

1. Make schema changes in `src/db/schema.ts`
2. Generate migration: `pnpm db:generate`
3. Apply locally: `pnpm db:migrate:local`
4. Verify in Drizzle Studio: `pnpm studio:local`
5. Start development: `pnpm dev`

## Deployment

```bash
# Deploy with migrations
pnpm db:migrate:prod && pnpm deploy

# Code quality checks
pnpm format
pnpm lint
pnpm check
```

## Available Commands

### Development
- `pnpm dev` - Start development server
- `pnpm dev:db` - Start with fresh migrations
- `pnpm db:fresh` - Reset local database

### Database
- `pnpm db:generate` - Generate migrations
- `pnpm db:migrate:local` - Apply migrations locally
- `pnpm db:migrate:prod` - Apply migrations to production
- `pnpm studio:local` - Open local Drizzle Studio
- `pnpm studio:remote` - Open remote Drizzle Studio

### Quality & Deployment
- `pnpm format` - Format code
- `pnpm lint` - Lint code
- `pnpm check` - Run checks
- `pnpm deploy` - Deploy to production
- `pnpm cf-typegen` - Generate Cloudflare types