import { EMAIL_FROM, RESEND_API_URL } from '../constants/services'
import { createVerificationEmailTemplate } from '../constants/templates'
import type {
  EmailResponse,
  ResendError,
  SendEmailParams,
  VerificationEmailData,
} from '../types/email'
import { ServerError, ValidationError } from '../types/error'

/**
 * Base email sending function
 */
export const sendEmail = async (
  apiKey: string,
  params: SendEmailParams
): Promise<EmailResponse> => {
  const response = await fetch(`${RESEND_API_URL}/emails`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(params),
  })

  if (!response.ok) {
    const errorData = (await response.json()) as ResendError

    if (response.status === 400) {
      throw new ValidationError('Invalid email parameters', {
        details: errorData,
        status: response.status,
      })
    }

    if (response.status === 429) {
      throw new ValidationError('Email rate limit exceeded', {
        details: errorData,
        status: response.status,
      })
    }

    throw new ServerError(errorData.message || 'Failed to send email', {
      details: errorData,
      status: response.status,
    })
  }

  const data = (await response.json()) as EmailResponse
  return data
}

/**
 * Send verification email
 */
export const sendVerificationEmail = async (
  apiKey: string,
  { to, firstName, verificationUrl }: VerificationEmailData
): Promise<EmailResponse> => {
  if (!to || !firstName || !verificationUrl) {
    throw new ValidationError('Missing required email data', {
      required: ['to', 'firstName', 'verificationUrl'],
      received: { to, firstName, verificationUrl },
    })
  }

  const html = createVerificationEmailTemplate({ firstName, verificationUrl })

  return sendEmail(apiKey, {
    from: EMAIL_FROM,
    to,
    subject: 'Verify your email address',
    html,
  })
}

/**
 * Send welcome email after verification
 */
export const sendWelcomeEmail = async (
  apiKey: string,
  to: string,
  firstName: string
): Promise<EmailResponse> => {
  const html = `
    <html>
      <body>
        <h1>Welcome to our platform, ${firstName}!</h1>
        <p>Thank you for verifying your email address. We're excited to have you on board.</p>
        <p>You can now access all features of our platform.</p>
      </body>
    </html>
  `

  return sendEmail(apiKey, {
    from: EMAIL_FROM,
    to,
    subject: 'Welcome to our platform!',
    html,
  })
}

/**
 * Send security alert email
 */
export const sendSecurityAlertEmail = async (
  apiKey: string,
  to: string,
  firstName: string,
  eventType: 'new_login' | 'password_changed' | 'password_reset',
  metadata: Record<string, unknown>
): Promise<EmailResponse> => {
  const subjects = {
    new_login: 'New login detected',
    password_changed: 'Your password has been changed',
    password_reset: 'Your password has been reset',
  }

  const messages = {
    new_login: 'We detected a new login to your account from a new device or location.',
    password_changed: 'Your account password has been successfully changed.',
    password_reset: 'Your account password has been reset successfully.',
  }

  const html = `
    <html>
      <body>
        <h1>Security Alert</h1>
        <p>Hi ${firstName},</p>
        <p>${messages[eventType]}</p>
        <p>Details:</p>
        <ul>
          ${Object.entries(metadata)
            .map(([key, value]) => `<li>${key}: ${value}</li>`)
            .join('')}
        </ul>
        <p>If this wasn't you, please contact support immediately.</p>
      </body>
    </html>
  `

  return sendEmail(apiKey, {
    from: EMAIL_FROM,
    to,
    subject: subjects[eventType],
    html,
  })
}

/**
 * Factory function to create email config
 */
export const createEmailConfig = (apiKey: string) => ({
  sendEmail: (params: SendEmailParams) => sendEmail(apiKey, params),
  sendVerificationEmail: (data: VerificationEmailData) => sendVerificationEmail(apiKey, data),
  sendWelcomeEmail: (to: string, firstName: string) => sendWelcomeEmail(apiKey, to, firstName),
  sendSecurityAlertEmail: (
    to: string,
    firstName: string,
    eventType: 'new_login' | 'password_changed' | 'password_reset',
    metadata: Record<string, unknown>
  ) => sendSecurityAlertEmail(apiKey, to, firstName, eventType, metadata),

  validateEmail: (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  },

  checkRateLimit: async (kv: KVNamespace, identifier: string): Promise<boolean> => {
    const key = `email_rate_limit:${identifier}`
    const limit = await kv.get(key)

    if (limit && Number.parseInt(limit) >= 5) {
      return false
    }

    const current = limit ? Number.parseInt(limit) : 0
    await kv.put(key, (current + 1).toString(), { expirationTtl: 3600 })

    return true
  },
})

export interface EmailTemplateData {
  firstName: string
  [key: string]: unknown
}

/**
 * Render email template with data
 */
export const renderTemplate = (template: string, data: EmailTemplateData): string => {
  return template.replace(/\${(\w+)}/g, (match, key) => String(data[key] ?? match))
}

/**
 * Get email domain from address
 */
export const getEmailDomain = (email: string): string => {
  const match = email.match(/@([^@]+)$/)
  if (!match) {
    throw new ValidationError('Invalid email format')
  }
  return match[1]
}

/**
 * Validate email domain is not disposable
 */
export const isDisposableEmail = async (domain: string): Promise<boolean> => {
  const disposableDomains = ['tempmail.com', 'throwawaymail.com']

  return disposableDomains.includes(domain.toLowerCase())
}
