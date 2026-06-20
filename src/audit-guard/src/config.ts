// Configuration for audit‑guard runtime options
export const WEBHOOK_URL = process.env.AUDIT_GUARD_WEBHOOK_URL || '';
export const WEBHOOK_TOKEN = process.env.AUDIT_GUARD_WEBHOOK_TOKEN || '';

// Log config values for monitoring changes
if (process.env.NODE_ENV !== 'test') {
  console.log('[Config] WEBHOOK_URL set to', WEBHOOK_URL);
  console.log('[Config] WEBHOOK_TOKEN set to', WEBHOOK_TOKEN ? '***' : '(empty)');
}
