export interface R2Metadata {
  uploadedBy?: string
  uploadedAt?: string
  originalName?: string
  contentType?: string
  checksum?: string
  tags?: string // JSON
}

export interface R2UploadOptions {
  metadata?: Partial<R2Metadata>
  cacheControl?: string
  contentType?: string
  contentDisposition?: string
  contentEncoding?: string
  contentLanguage?: string

  maxSizeInMB?: number
  allowedTypes?: string[]
  validateChecksum?: boolean
}

export interface R2ImageUploadOptions extends R2UploadOptions {
  maxWidth?: number
  maxHeight?: number
  quality?: number
  format?: 'jpeg' | 'png' | 'webp'
}

export interface R2DownloadOptions {
  range?: {
    offset: number
    length: number
  } | null
  asStream?: boolean
}

export interface R2ListOptions {
  prefix?: string
  delimiter?: string
  cursor?: string
  limit?: number
  includeMetadata?: boolean
}

export interface R2ObjectInfo {
  key: string
  size: number
  etag: string
  uploaded: Date
  metadata?: R2Metadata
  httpEtag?: string
}

export interface R2ListResult {
  objects: R2ObjectInfo[]
  truncated: boolean
  cursor?: string
  delimitedPrefixes: string[]
}
