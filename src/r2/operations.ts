import type {
  R2DownloadOptions,
  R2ImageUploadOptions,
  R2ListOptions,
  R2ListResult,
  R2Metadata,
  R2ObjectInfo,
  R2UploadOptions,
} from '../types/r2'
import { mapR2ObjectToInfo, parseMetadata, sanitizeMetadata } from './utils'

export const uploadFile = async (
  bucket: R2Bucket,
  file: File | Blob | ArrayBuffer,
  key: string,
  options: R2UploadOptions = {}
): Promise<R2ObjectInfo> => {
  const { maxSizeInMB = 100, allowedTypes = [] } = options

  if (file instanceof File || file instanceof Blob) {
    if (file.size > maxSizeInMB * 1024 * 1024) {
      throw new Error(`File size exceeds ${maxSizeInMB}MB limit`)
    }

    if (allowedTypes.length && file instanceof File && !allowedTypes.includes(file.type)) {
      throw new Error('Invalid file type')
    }
  }

  const metadata: R2Metadata = {
    uploadedAt: new Date().toISOString(),
    contentType:
      options.contentType || (file instanceof File ? file.type : 'application/octet-stream'),
    ...(options.metadata || {}),
    tags: options.metadata?.tags ? JSON.stringify(options.metadata.tags) : undefined,
  }

  const result = await bucket.put(key, file, {
    httpMetadata: {
      contentType: metadata.contentType,
      cacheControl: options.cacheControl,
      contentDisposition: options.contentDisposition,
      contentEncoding: options.contentEncoding,
      contentLanguage: options.contentLanguage,
    },
    customMetadata: sanitizeMetadata(metadata),
  })

  return mapR2ObjectToInfo(result)
}

export const uploadImage = async (
  bucket: R2Bucket,
  image: File | Blob,
  key: string,
  options: R2ImageUploadOptions = {}
): Promise<R2ObjectInfo> => {
  const validImageTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif']

  if (image instanceof File && !validImageTypes.includes(image.type)) {
    throw new Error('Invalid image type')
  }

  return uploadFile(bucket, image, key, {
    ...options,
    allowedTypes: validImageTypes,
  })
}

export const downloadFile = async (
  bucket: R2Bucket,
  key: string,
  options: R2DownloadOptions = {}
): Promise<R2ObjectBody | null> => {
  return bucket.get(key, {
    range: options.range
      ? {
          offset: options.range.offset,
          length: options.range.length,
        }
      : undefined,
  })
}

export const deleteFile = async (bucket: R2Bucket, key: string): Promise<void> => {
  await bucket.delete(key)
}

export const deleteFiles = async (bucket: R2Bucket, keys: string[]): Promise<void> => {
  await bucket.delete(keys)
}

export const exists = async (bucket: R2Bucket, key: string): Promise<boolean> => {
  const object = await bucket.head(key)
  return object !== null
}

export const getMetadata = async (bucket: R2Bucket, key: string): Promise<R2Metadata | null> => {
  const object = await bucket.head(key)
  return object?.customMetadata ? parseMetadata(object.customMetadata) : null
}

export const listFiles = async (
  bucket: R2Bucket,
  options: R2ListOptions = {}
): Promise<R2ListResult> => {
  const { prefix, delimiter, cursor, limit } = options

  const result = await bucket.list({
    prefix,
    delimiter,
    cursor,
    limit,
    include: options.includeMetadata ? ['customMetadata', 'httpMetadata'] : undefined,
  })

  return {
    objects: result.objects.map(mapR2ObjectToInfo),
    truncated: result.truncated,
    cursor: result.truncated ? result.cursor : undefined,
    delimitedPrefixes: result.delimitedPrefixes,
  }
}
