import { Hono } from 'hono'
import type { BaseEnv } from '../types/hono'
import userRouter from './user'

const rpcRouter = new Hono<BaseEnv>()

const router = rpcRouter.route('/user', userRouter)

export default router

export type AppType = typeof router
