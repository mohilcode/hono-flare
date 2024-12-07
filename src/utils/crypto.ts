import { KEY_LENGTH, PBKDF2_ITERATIONS, SALT_LENGTH, TOKEN_LENGTH } from '../constants/services'
import { ValidationError } from '../types/error'

const _bufferToBase64 = (buffer: ArrayBuffer): string => {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

const _base64ToBuffer = (base64: string): ArrayBuffer => {
  if (!/^[A-Za-z0-9_-]+$/.test(base64)) {
    throw new ValidationError('Invalid base64 string format')
  }

  const padding = '='.repeat((4 - (base64.length % 4)) % 4)
  const b64 = (base64 + padding).replace(/\-/g, '+').replace(/_/g, '/')
  const rawData = atob(b64)
  const buffer = new Uint8Array(rawData.length)

  for (let i = 0; i < rawData.length; i++) {
    buffer[i] = rawData.charCodeAt(i)
  }

  return buffer.buffer
}

const _generateRandomBytes = (length: number): ArrayBuffer => {
  if (length <= 0) {
    throw new ValidationError('Length must be positive')
  }
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes.buffer
}

const _timingSafeEqual = (a: string, b: string): boolean => {
  if (typeof a !== 'string' || typeof b !== 'string') {
    throw new ValidationError('Both arguments must be strings')
  }

  if (a.length !== b.length) {
    return false
  }

  const aBuffer = new TextEncoder().encode(a)
  const bBuffer = new TextEncoder().encode(b)

  try {
    return crypto.subtle.timingSafeEqual(aBuffer, bBuffer)
  } catch {
    return false
  }
}

export const generateRandomToken = (): string => {
  return _bufferToBase64(_generateRandomBytes(TOKEN_LENGTH))
}

export const hashPassword = async (password: string): Promise<string> => {
  if (!password) {
    throw new ValidationError('Password is required')
  }

  const salt = _generateRandomBytes(SALT_LENGTH)
  const encoder = new TextEncoder()
  const passwordBuffer = encoder.encode(password)

  const key = await crypto.subtle.importKey('raw', passwordBuffer, { name: 'PBKDF2' }, false, [
    'deriveBits',
  ])

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: { name: 'SHA-256' },
    },
    key,
    KEY_LENGTH * 8
  )

  const hashBuffer = new Uint8Array(SALT_LENGTH + KEY_LENGTH)
  hashBuffer.set(new Uint8Array(salt), 0)
  hashBuffer.set(new Uint8Array(derivedBits), SALT_LENGTH)

  return _bufferToBase64(hashBuffer.buffer)
}

export const verifyPassword = async (password: string, hashString: string): Promise<boolean> => {
  if (!password || !hashString) {
    throw new ValidationError('Password and hash are required')
  }

  const hashBuffer = _base64ToBuffer(hashString)

  const salt = hashBuffer.slice(0, SALT_LENGTH)
  const storedKey = hashBuffer.slice(SALT_LENGTH)

  const encoder = new TextEncoder()
  const passwordBuffer = encoder.encode(password)

  const key = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveBits'])

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
}

export const generateId = (): string => {
  return _bufferToBase64(_generateRandomBytes(16))
}

export const generateCsrfToken = (): string => {
  return generateRandomToken()
}

export const verifyCsrfToken = (token: string, storedToken: string): boolean => {
  if (!token || !storedToken) {
    throw new ValidationError('Token and stored token are required')
  }
  return _timingSafeEqual(token, storedToken)
}

export const generateAuthKeyPair = async (): Promise<CryptoKeyPair> => {
  return (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]).buffer,
      hash: { name: 'SHA-256' },
    },
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair
}
