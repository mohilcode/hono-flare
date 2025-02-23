import { RESEND_API_URL } from '../constants/services'
import type { EmailResponse, ResendError, SendEmailParams } from '../types/email'
import { getBindings } from './context'

export const sendEmail = async (params: SendEmailParams): Promise<EmailResponse> => {
  const response = await fetch(`${RESEND_API_URL}/emails`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${getBindings().RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(params),
  })

  const data = (await response.json()) as EmailResponse | ResendError

  if (!response.ok) {
    throw data as ResendError
  }

  return data as EmailResponse
}
