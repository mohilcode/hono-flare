export const isValidToken = (token: string): boolean => {
  const tokenRegex = /^[A-Za-z0-9_-]{21,}$/
  return tokenRegex.test(token)
}

export const getVerificationKey = (token: string): string => {
  return `email_verify:${token}`
}

export const getRateLimitKey = (identifier: string): string => {
  return `rate_limit:email_verify:${identifier}`
}
