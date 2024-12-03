export const createKV = (env: CloudflareBindings) => ({
  users: env.KV,
})
