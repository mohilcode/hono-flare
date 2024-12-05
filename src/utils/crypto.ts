import { ErrorCodes } from '../constants/error'
import { KEY_LENGTH, PBKDF2_ITERATIONS, SALT_LENGTH, TOKEN_LENGTH } from '../constants/services'
import { createError } from '../lib/error'
import { HttpStatusCode } from '../types/http'

/**
 * Converts ArrayBuffer to base64 string
 */
const bufferToBase64 = (buffer: ArrayBuffer): string => {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/**
 * Converts base64 string to ArrayBuffer
 */
const base64ToBuffer = (base64: string): ArrayBuffer => {
  const padding = '='.repeat((4 - (base64.length % 4)) % 4)
  const b64 = (base64 + padding).replace(/\-/g, '+').replace(/_/g, '/')
  const rawData = atob(b64)
  const buffer = new Uint8Array(rawData.length)

  for (let i = 0; i < rawData.length; i++) {
    buffer[i] = rawData.charCodeAt(i)
  }

  return buffer.buffer
}

/**
 * Generates cryptographically secure random bytes
 */
const generateRandomBytes = (length: number): ArrayBuffer => {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes.buffer
}

/**
 * Generates a secure random token
 */
export const generateToken = (): string => {
  return bufferToBase64(generateRandomBytes(TOKEN_LENGTH))
}

/**
 * Hash password using PBKDF2
 */
export const hashPassword = async (password: string): Promise<string> => {
  try {
    const salt = generateRandomBytes(SALT_LENGTH)
    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password)

    const key = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      {
        name: 'PBKDF2',
      },
      false,
      ['deriveBits']
    )

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: {
          name: 'SHA-256',
        },
      },
      key,
      KEY_LENGTH * 8
    )

    const hashBuffer = new Uint8Array(SALT_LENGTH + KEY_LENGTH)
    hashBuffer.set(new Uint8Array(salt), 0)
    hashBuffer.set(new Uint8Array(derivedBits), SALT_LENGTH)

    return bufferToBase64(hashBuffer.buffer)
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Password hashing failed',
      { error }
    )
  }
}

/**
 * Verify password against hash
 */
export const verifyPassword = async (password: string, hashString: string): Promise<boolean> => {
  try {
    const hashBuffer = base64ToBuffer(hashString)

    const salt = hashBuffer.slice(0, SALT_LENGTH)
    const storedKey = hashBuffer.slice(SALT_LENGTH)

    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password)

    const key = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, [
      'deriveBits',
    ])

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      key,
      KEY_LENGTH * 8
    )

    return crypto.subtle.timingSafeEqual(derivedBits, storedKey)
  } catch (error) {
    throw createError(
      ErrorCodes.SERVER_ERROR,
      HttpStatusCode.INTERNAL_SERVER_ERROR,
      'Password verification failed',
      { error }
    )
  }
}

/**
 * Generate cryptographically secure random ID
 */
export const generateId = (): string => {
  const bytes = generateRandomBytes(16)
  return bufferToBase64(bytes)
}

/**
 * Timing-safe string comparison
 */
export const timingSafeEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) {
    return false
  }

  const aBuffer = new TextEncoder().encode(a)
  const bBuffer = new TextEncoder().encode(b)

  return crypto.subtle.timingSafeEqual(aBuffer, bBuffer)
}

/**
 * Generate CSRF token
 */
export const generateCsrfToken = (): string => {
  return generateToken()
}

/**
 * Verify CSRF token
 */
export const verifyCsrfToken = (token: string, storedToken: string): boolean => {
  return timingSafeEqual(token, storedToken)
}
