// Configuration for audit‑guard runtime options
export const WEBHOOK_URL = process.env.AUDIT_GUARD_WEBHOOK_URL || '';
export const WEBHOOK_TOKEN = process.env.AUDIT_GUARD_WEBHOOK_TOKEN || '';

// On‑call roster configuration
export const ONCALL_CONTACTS = process.env.ONCALL_CONTACTS || '';
export const ONCALL_ROTATION_INTERVAL = (process.env.ONCALL_ROTATION_INTERVAL || 'weekly') as 'daily' | 'weekly';
export const ONCALL_PAGE_WEBHOOK_URL = process.env.ONCALL_PAGE_WEBHOOK_URL || WEBHOOK_URL;

// Log config values for monitoring changes
if (process.env.NODE_ENV !== 'test') {
  console.log('[Config] WEBHOOK_URL set to', WEBHOOK_URL);
  console.log('[Config] WEBHOOK_TOKEN set to', WEBHOOK_TOKEN ? '***' : '(empty)');
  console.log('[Config] ONCALL_ROTATION_INTERVAL set to', ONCALL_ROTATION_INTERVAL);
}
