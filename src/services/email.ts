import { ErrorCodes } from '../constants/error'
import { EMAIL_FROM, RESEND_API_URL } from '../constants/services'
import { createVerificationEmailTemplate } from '../constants/templates'
import { createError } from '../lib/error'
import type {
  EmailResponse,
  ResendError,
  SendEmailParams,
  VerificationEmailData,
} from '../types/email'
import type { HttpStatus } from '../types/http'

export const sendEmail = async (
  apiKey: string,
  params: SendEmailParams
): Promise<EmailResponse> => {
  try {
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
      throw createError(
        ErrorCodes.SERVER_ERROR,
        response.status as HttpStatus,
        errorData.message || 'Failed to send email'
      )
    }

    return (await response.json()) as EmailResponse
  } catch (error) {
    if (error instanceof Error) {
      throw createError(ErrorCodes.SERVER_ERROR, 500 as HttpStatus, error.message, {
        error: error.message,
      })
    }
    throw createError(ErrorCodes.SERVER_ERROR, 500 as HttpStatus, 'Failed to send email')
  }
}

export const sendVerificationEmail = async (
  apiKey: string,
  { to, firstName, verificationUrl }: VerificationEmailData
): Promise<EmailResponse> => {
  const html = createVerificationEmailTemplate({ firstName, verificationUrl })

  return sendEmail(apiKey, {
    from: EMAIL_FROM,
    to,
    subject: 'Verify your email address',
    html,
  })
}

export const createEmailConfig = (apiKey: string) => ({
  sendVerificationEmail: (data: VerificationEmailData) => sendVerificationEmail(apiKey, data),
  sendEmail: (params: SendEmailParams) => sendEmail(apiKey, params),
})
