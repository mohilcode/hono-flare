export type KVValueType = string | ReadableStream | ArrayBuffer

export type JSONValue =
  | string
  | number
  | boolean
  | null
  | JSONValue[]
  | { [key: string]: JSONValue }

export interface BaseKVMetadata {
  createdAt?: string
  updatedAt?: string
  version?: string
  contentType?: string
}

export interface KVBaseOptions {
  expiration?: number
  expirationTtl?: number
  metadata?: BaseKVMetadata

  type?: 'text' | 'json' | 'arrayBuffer' | 'stream'
  cacheTtl?: number
}

export interface KVGetWithMetadataResult<T = unknown, M = BaseKVMetadata> {
  value: T | null
  metadata: M | null
}

export interface KVListOptions {
  prefix?: string
  limit?: number
  cursor?: string
}

export interface KVListResult<M = BaseKVMetadata> {
  keys: {
    name: string
    expiration?: number
    metadata?: M
  }[]
  list_complete: boolean
  cursor?: string
}

export interface TypedKV<T = unknown, M = BaseKVMetadata> {
  get(key: string, type?: KVBaseOptions['type']): Promise<T | null>
  getWithMetadata(key: string, options?: KVBaseOptions): Promise<KVGetWithMetadataResult<T, M>>
  put(key: string, value: string, options?: KVBaseOptions): Promise<void>
  delete(key: string): Promise<void>
  list(options?: KVListOptions): Promise<KVListResult<M>>
}
