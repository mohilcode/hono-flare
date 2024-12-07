import { EMAIL_FROM, RESEND_API_URL } from '../constants/services'
import templates from '../constants/templates'
import type {
  EmailConfig,
  EmailResponse,
  ResendError,
  SecurityAlertEventType,
  SendEmailParams,
} from '../types/email'
import { ServerError, ValidationError } from '../types/error'

const _handleError = (status: number, errorData: ResendError): never => {
  if (status === 400) {
    throw new ValidationError('Invalid email parameters', {
      details: errorData,
      status,
    })
  }

  if (status === 429) {
    throw new ValidationError('Email rate limit exceeded', {
      details: errorData,
      status,
    })
  }

  throw new ServerError(errorData.message || 'Failed to send email', {
    details: errorData,
    status,
  })
}

const _validateRequiredFields = (fields: Record<string, unknown>): void => {
  const missingFields = Object.entries(fields)
    .filter(([_, value]) => !value)
    .map(([key]) => key)

  if (missingFields.length > 0) {
    throw new ValidationError('Missing required email data', {
      required: Object.keys(fields),
      missing: missingFields,
      received: fields,
    })
  }
}

const _getSecurityAlertSubject = (eventType: SecurityAlertEventType['type']): string => {
  const subjects = {
    new_login: 'New login detected',
    password_changed: 'Your password has been changed',
    password_reset: 'Your password has been reset',
  }
  return subjects[eventType]
}

export const createEmailService = (config: EmailConfig) => {
  const { apiKey } = config

  const sendEmail = async (params: SendEmailParams): Promise<EmailResponse> => {
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
      _handleError(response.status, errorData)
    }

    return (await response.json()) as EmailResponse
  }

  const sendVerificationEmail = async (params: {
    to: string
    firstName: string
    verificationUrl: string
  }): Promise<EmailResponse> => {
    const { to, firstName, verificationUrl } = params
    _validateRequiredFields({ to, firstName, verificationUrl })

    return sendEmail({
      from: EMAIL_FROM,
      to,
      subject: 'Verify your email address',
      html: templates.verification({ firstName, verificationUrl }),
    })
  }

  const sendInitiatePasswordEmail = async (params: {
    to: string
    firstName: string
    resetUrl: string
  }): Promise<EmailResponse> => {
    const { to, firstName, resetUrl } = params
    _validateRequiredFields({ to, firstName, resetUrl })

    return sendEmail({
      from: EMAIL_FROM,
      to,
      subject: 'Password Reset Request',
      html: templates.passwordReset({ firstName, resetUrl }),
    })
  }

  const sendPasswordResetEmail = async (params: {
    to: string
    firstName: string
  }): Promise<EmailResponse> => {
    const { to, firstName } = params
    _validateRequiredFields({ to, firstName })

    return sendEmail({
      from: EMAIL_FROM,
      to,
      subject: 'Password Reset Successful',
      html: templates.passwordResetSuccess({ firstName }),
    })
  }

  const sendWelcomeEmail = async (params: {
    to: string
    firstName: string
  }): Promise<EmailResponse> => {
    const { to, firstName } = params
    _validateRequiredFields({ to, firstName })

    return sendEmail({
      from: EMAIL_FROM,
      to,
      subject: 'Welcome to our platform!',
      html: templates.welcome({ firstName }),
    })
  }

  const sendSecurityAlertEmail = async (params: {
    to: string
    firstName: string
    event: SecurityAlertEventType
  }): Promise<EmailResponse> => {
    const { to, firstName, event } = params
    _validateRequiredFields({ to, firstName, event })

    return sendEmail({
      from: EMAIL_FROM,
      to,
      subject: _getSecurityAlertSubject(event.type),
      html: templates.securityAlert({ firstName, eventType: event.type, metadata: event.metadata }),
    })
  }

  return {
    sendEmail,
    sendWelcomeEmail,
    sendVerificationEmail,
    sendPasswordResetEmail,
    sendSecurityAlertEmail,
    sendInitiatePasswordEmail,
  }
}

export const createEmailConfig = (apiKey: string, rateLimitKV?: KVNamespace) => {
  return createEmailService({ apiKey, rateLimitKV })
}

export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

export const getEmailDomain = (email: string): string => {
  const match = email.match(/@([^@]+)$/)
  if (!match) {
    throw new ValidationError('Invalid email format')
  }
  return match[1]
}

export const isDisposableEmail = async (domain: string): Promise<boolean> => {
  const disposableDomains = ['tempmail.com', 'throwawaymail.com']
  return disposableDomains.includes(domain.toLowerCase())
}
