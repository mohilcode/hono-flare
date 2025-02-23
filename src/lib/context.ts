import { getContext } from 'hono/context-storage'
import type { BaseEnv } from '../types/hono'

export const getBindings = () => {
  return getContext<BaseEnv>().env
}

export const getDB = () => {
  return getBindings().DB
}

export const getKV = () => {
  return getBindings().KV
}

export const getR2 = () => {
  return getBindings().R2
}
