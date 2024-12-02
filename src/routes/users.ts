import { eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { ErrorCodes } from '../constants/error'
import { createDB } from '../db'
import { users } from '../db/schema'
import { createError } from '../lib/error'
import { HttpStatusCode } from '../types/http'

const route = new Hono<{ Bindings: CloudflareBindings }>()

const validateId = (id: number): boolean => {
  return !Number.isNaN(id) && Number.isInteger(id) && id > 0
}

route.get('/', async c => {
  const db = createDB(c.env)
  try {
    const allUsers = await db.select().from(users)
    return c.json({ users: allUsers })
  } catch (error) {
    console.error('Error fetching users:', error)
    throw createError(ErrorCodes.SERVER_ERROR, HttpStatusCode.INTERNAL_SERVER_ERROR)
  }
})

route.get('/:id', async c => {
  const db = createDB(c.env)
  const id = Number(c.req.param('id'))

  if (!validateId(id)) {
    throw createError(
      ErrorCodes.VALIDATION_ERROR,
      HttpStatusCode.BAD_REQUEST,
      'Invalid user ID format - must be a positive integer'
    )
  }

  try {
    const user = await db.select().from(users).where(eq(users.id, id))

    if (!user.length) {
      throw createError(ErrorCodes.USER_NOT_FOUND, HttpStatusCode.NOT_FOUND)
    }

    return c.json({ user: user[0] })
  } catch (error) {
    console.error('Error fetching user:', error)
    throw createError(ErrorCodes.SERVER_ERROR, HttpStatusCode.INTERNAL_SERVER_ERROR)
  }
})

route.post('/', async c => {
  const db = createDB(c.env)

  try {
    const { email, name } = await c.req.json()

    if (!email || !name) {
      throw createError(
        ErrorCodes.VALIDATION_ERROR,
        HttpStatusCode.BAD_REQUEST,
        'Email and name are required',
        { received: { email, name } }
      )
    }

    const newUser = await db
      .insert(users)
      .values({
        email,
        name,
      })
      .returning()

    return c.json({ user: newUser[0] }, HttpStatusCode.CREATED)
  } catch (error) {
    console.error('Error creating user:', error)
    throw createError(ErrorCodes.SERVER_ERROR, HttpStatusCode.INTERNAL_SERVER_ERROR)
  }
})

route.put('/:id', async c => {
  const db = createDB(c.env)
  const id = Number(c.req.param('id'))

  if (!validateId(id)) {
    throw createError(
      ErrorCodes.VALIDATION_ERROR,
      HttpStatusCode.BAD_REQUEST,
      'Invalid user ID format - must be a positive integer'
    )
  }

  try {
    const { email, name } = await c.req.json()
    const updateData: Partial<typeof users.$inferInsert> = {}

    if (email) {
      updateData.email = email
    }
    if (name) {
      updateData.name = name
    }

    if (Object.keys(updateData).length === 0) {
      throw createError(
        ErrorCodes.VALIDATION_ERROR,
        HttpStatusCode.BAD_REQUEST,
        'No data provided for update'
      )
    }

    const updatedUser = await db.update(users).set(updateData).where(eq(users.id, id)).returning()

    if (!updatedUser.length) {
      throw createError(ErrorCodes.USER_NOT_FOUND, HttpStatusCode.NOT_FOUND)
    }

    return c.json({ user: updatedUser[0] })
  } catch (error) {
    console.error('Error updating user:', error)
    throw createError(ErrorCodes.SERVER_ERROR, HttpStatusCode.INTERNAL_SERVER_ERROR)
  }
})

route.delete('/:id', async c => {
  const db = createDB(c.env)
  const id = Number(c.req.param('id'))

  if (!validateId(id)) {
    throw createError(
      ErrorCodes.VALIDATION_ERROR,
      HttpStatusCode.BAD_REQUEST,
      'Invalid user ID format - must be a positive integer'
    )
  }

  try {
    const deletedUser = await db.delete(users).where(eq(users.id, id)).returning()

    if (!deletedUser.length) {
      throw createError(ErrorCodes.USER_NOT_FOUND, HttpStatusCode.NOT_FOUND)
    }

    return c.json({
      message: 'User deleted successfully',
      user: deletedUser[0],
    })
  } catch (error) {
    console.error('Error deleting user:', error)
    throw createError(ErrorCodes.SERVER_ERROR, HttpStatusCode.INTERNAL_SERVER_ERROR)
  }
})

export default route
