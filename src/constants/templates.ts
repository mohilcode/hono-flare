import type {
  EmailTemplateData,
  PasswordResetTemplateData,
  SecurityAlertTemplateData,
  VerificationTemplateData,
} from '../types/email'

const templates = {
  verification: ({ firstName, verificationUrl }: VerificationTemplateData): string => `
    <html>
      <body>
        <h1>Welcome, ${firstName}!</h1>
        <p>Please verify your email address by clicking the link below:</p>
        <a href="${verificationUrl}">Verify Email</a>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
      </body>
    </html>
  `,

  welcome: ({ firstName }: EmailTemplateData): string => `
    <html>
      <body>
        <h1>Welcome to our platform, ${firstName}!</h1>
        <p>Thank you for verifying your email address. We're excited to have you on board.</p>
        <p>You can now access all features of our platform.</p>
      </body>
    </html>
  `,

  passwordReset: ({ firstName, resetUrl }: PasswordResetTemplateData): string => `
    <html>
      <body>
        <h1>Password Reset Request</h1>
        <p>Hi ${firstName},</p>
        <p>We received a request to reset your password. Click the link below to reset it:</p>
        <a href="${resetUrl}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
      </body>
    </html>
  `,

  passwordResetSuccess: ({ firstName }: EmailTemplateData): string => `<html>
    <body>
      <h1>Password Reset Successful</h1>
      <p>Hi ${firstName},</p>
      <p>Your password has been successfully reset.</p>
      <p>If you didn't make this change, please contact our support team immediately.</p>
    </body>
  </html>`,

  securityAlert: ({ firstName, eventType, metadata }: SecurityAlertTemplateData): string => {
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

    return `
      <html>
        <body>
          <h1>${subjects[eventType]}</h1>
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
  },
}

export default templates
