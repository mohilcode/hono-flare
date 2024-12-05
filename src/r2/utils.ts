import type { R2Metadata, R2ObjectInfo } from '../types/r2'

export const sanitizeMetadata = (metadata: R2Metadata): Record<string, string> => {
  const sanitized: Record<string, string> = {}
  for (const [key, value] of Object.entries(metadata)) {
    if (value !== undefined) {
      sanitized[key] = String(value)
    }
  }
  return sanitized
}

export const parseMetadata = (metadata: Record<string, string>): R2Metadata => {
  const parsed: R2Metadata = {
    ...metadata,
    ...(metadata.tags && { tags: JSON.parse(metadata.tags) }),
  }
  return parsed
}

export const mapR2ObjectToInfo = (obj: R2Object): R2ObjectInfo => ({
  key: obj.key,
  size: obj.size,
  etag: obj.etag,
  uploaded: new Date(obj.uploaded),
  metadata: obj.customMetadata ? parseMetadata(obj.customMetadata) : undefined,
  httpEtag: obj.httpEtag,
})
