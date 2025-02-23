import { PRODUCTION } from '../constants/env'

export const RESEND_API_URL = 'https://api.resend.com'

export const EMAIL_FROM = 'Upresume <mohil@account.upresume.io>'

export const DOMAIN = new URL(PRODUCTION).hostname
