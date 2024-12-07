export interface EmailTemplateData {
  firstName: string
  [key: string]: unknown
}

export interface SendEmailParams {
  from: string
  to: string | string[]
  subject: string
  html?: string
  text?: string
  replyTo?: string | string[]
  cc?: string | string[]
  bcc?: string | string[]
}

export interface EmailResponse {
  id: string
}

export interface ResendError {
  statusCode: number
  name: string
  message: string
}

export interface EmailConfig {
  apiKey: string
  rateLimitKV?: KVNamespace
}

export interface SecurityAlertEventType {
  type: 'new_login' | 'password_changed' | 'password_reset'
  metadata: Record<string, unknown>
}

export interface VerificationTemplateData extends EmailTemplateData {
  verificationUrl: string
}

export interface PasswordResetTemplateData extends EmailTemplateData {
  resetUrl: string
}

export interface SecurityAlertTemplateData extends EmailTemplateData {
  eventType: 'new_login' | 'password_changed' | 'password_reset'
  metadata: Record<string, unknown>
}
