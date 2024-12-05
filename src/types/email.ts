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

export interface EmailError {
  statusCode: number
  message: string
  name: string
}

export interface VerificationEmailData {
  to: string
  firstName: string
  verificationUrl: string
}

export interface ResendError {
  statusCode: number
  name: string
  message: string
}
