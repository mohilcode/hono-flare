export const createVerificationEmailTemplate = (data: {
  firstName: string
  verificationUrl: string
}): string => {
  return `
    <html>
      <body>
        <h1>Welcome, ${data.firstName}!</h1>
        <p>Please verify your email address by clicking the link below:</p>
        <a href="${data.verificationUrl}">Verify Email</a>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
      </body>s
    </html>
  `
}

export const createPasswordResetEmailTemplate = ({
  firstName,
  resetUrl,
}: {
  firstName: string
  resetUrl: string
}): string => {
  return `<html>
    <body>
      <h1>Password Reset Request</h1>
      <p>Hi ${firstName},</p>
      <p>We received a request to reset your password. Click the link below to reset it:</p>
      <a href="${resetUrl}">Reset Password</a>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, you can safely ignore this email.</p>
    </body>
  </html>
`
}

export const createPasswordResetSuccessfulTemplate = (firstName: string): string => {
  return `<html>
    <body>
      <h1>Password Reset Successful</h1>
      <p>Hi ${firstName},</p>
      <p>Your password has been successfully reset.</p>
    </body>
  </html>
`
}
