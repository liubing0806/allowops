export class ApiError extends Error {
  constructor(
    public readonly key: string,
    public readonly code?: number,
    // ErrorDetail.reason, for example OUTPUT_PENDING.
    public readonly reason?: string,
    // ErrorDetail.retry_after in milliseconds.
    public readonly retryAfterMs?: number,
  ) {
    super(key)
  }
}
