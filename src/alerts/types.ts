/**
 * Alert System Types
 * Defines all types for the alert system including alert types, rules, and notifications.
 */

// ============================================================================
// Alert Types
// ============================================================================

/** Types of alerts that can be generated */
export type AlertType =
  | 'risk_event'       // High-risk detection event
  | 'quota_warning'    // Quota usage warning (80%, 90%)
  | 'quota_exceeded'   // Quota limit exceeded
  | 'anomaly';         // Anomalous behavior detected

/** Severity levels for alerts */
export type AlertSeverity = 'info' | 'warning' | 'error' | 'critical';

/** Status of an alert */
export type AlertStatus = 'active' | 'acknowledged' | 'resolved';

// ============================================================================
// Alert Rule Configuration
// ============================================================================

/** Configuration for a single alert rule */
export interface AlertRule {
  /** Unique identifier for the rule */
  id: string;
  /** Type of alert this rule generates */
  type: AlertType;
  /** Human-readable name for the rule */
  name: string;
  /** Description of when this alert triggers */
  description: string;
  /** Threshold value for triggering (e.g., 80 for 80% quota) */
  threshold: number;
  /** Whether this rule is currently enabled */
  enabled: boolean;
  /** Notification channels to use for this rule */
  channels: NotificationChannel[];
  /** Cooldown period in seconds between alerts of the same type */
  cooldownSeconds: number;
  /** Additional conditions for the rule */
  conditions?: AlertCondition[];
}

/** Condition for triggering an alert */
export interface AlertCondition {
  /** Field to check */
  field: string;
  /** Comparison operator */
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'matches';
  /** Value to compare against */
  value: string | number | boolean;
}

// ============================================================================
// Alert Entity
// ============================================================================

/** An alert instance that has been triggered */
export interface Alert {
  /** Unique identifier for the alert */
  id: string;
  /** Type of alert */
  type: AlertType;
  /** Severity level */
  severity: AlertSeverity;
  /** Current status */
  status: AlertStatus;
  /** Short title for the alert */
  title: string;
  /** Detailed message describing the alert */
  message: string;
  /** When the alert was created */
  timestamp: string;
  /** When the alert was last updated */
  updatedAt?: string;
  /** Application ID this alert relates to */
  appId?: string;
  /** User ID this alert relates to */
  userId?: string;
  /** Agent ID this alert relates to */
  agentId?: string;
  /** Additional details about the alert */
  details: AlertDetails;
  /** ID of the rule that triggered this alert */
  ruleId: string;
  /** Who acknowledged this alert (if applicable) */
  acknowledgedBy?: string;
  /** When this alert was acknowledged */
  acknowledgedAt?: string;
  /** Resolution notes (if resolved) */
  resolutionNotes?: string;
}

/** Detailed information about an alert */
export interface AlertDetails {
  /** Original event data that triggered the alert */
  eventData?: Record<string, unknown>;
  /** Risk level if this is a risk event */
  riskLevel?: 'no_risk' | 'low_risk' | 'medium_risk' | 'high_risk';
  /** Categories involved in the alert */
  categories?: string[];
  /** Score if applicable */
  score?: number;
  /** Quota usage percentage if this is a quota alert */
  quotaPercentage?: number;
  /** Quota type if this is a quota alert */
  quotaType?: 'checks' | 'tokens';
  /** Anomaly type if this is an anomaly alert */
  anomalyType?: 'high_risk_burst' | 'unusual_pattern' | 'rate_limit_exceeded';
  /** Number of events in the time window (for anomaly alerts) */
  eventCount?: number;
  /** Time window in seconds (for anomaly alerts) */
  timeWindowSeconds?: number;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

// ============================================================================
// Notification Configuration
// ============================================================================

/** Types of notification channels */
export type NotificationChannelType = 'email' | 'webhook' | 'dashboard';

/** Configuration for a notification channel */
export interface NotificationChannel {
  /** Type of notification channel */
  type: NotificationChannelType;
  /** Whether this channel is enabled */
  enabled: boolean;
  /** Channel-specific configuration */
  config: EmailConfig | WebhookConfig | DashboardConfig;
}

/** Email notification configuration */
export interface EmailConfig {
  /** Recipient email addresses */
  recipients: string[];
  /** Email subject template */
  subjectTemplate?: string;
  /** Email body template (HTML) */
  bodyTemplate?: string;
  /** Include event details in email */
  includeDetails: boolean;
}

/** Webhook notification configuration */
export interface WebhookConfig {
  /** Webhook URL to POST to */
  url: string;
  /** Custom HTTP headers */
  headers?: Record<string, string>;
  /** HTTP timeout in milliseconds */
  timeoutMs?: number;
  /** Number of retry attempts on failure */
  retryAttempts?: number;
  /** Delay between retries in milliseconds */
  retryDelayMs?: number;
  /** Secret key for signing webhook payloads */
  secretKey?: string;
}

/** Dashboard notification configuration */
export interface DashboardConfig {
  /** Show notification as a popup */
  showPopup: boolean;
  /** Play sound on notification */
  playSound: boolean;
  /** Auto-dismiss after seconds (0 = no auto-dismiss) */
  autoDismissSeconds?: number;
  /** Subscribe to specific alert types (empty = all) */
  subscribedTypes?: AlertType[];
}

// ============================================================================
// Alert Configuration
// ============================================================================

/** Complete alert configuration for an application or user */
export interface AlertConfiguration {
  /** Unique identifier for this configuration */
  id: string;
  /** Application ID this configuration belongs to */
  appId?: string;
  /** User ID this configuration belongs to */
  userId?: string;
  /** Alert rules configured */
  rules: AlertRule[];
  /** Global notification channels */
  channels: NotificationChannel[];
  /** Global settings */
  settings: AlertSettings;
  /** When this configuration was created */
  createdAt: string;
  /** When this configuration was last updated */
  updatedAt: string;
}

/** Global alert settings */
export interface AlertSettings {
  /** Enable/disable all alerts */
  enabled: boolean;
  /** Default cooldown period in seconds */
  defaultCooldownSeconds: number;
  /** Maximum alerts to keep in history */
  maxHistorySize: number;
  /** Enable alert digest (summary emails) */
  enableDigest: boolean;
  /** Digest frequency in hours */
  digestFrequencyHours: number;
  /** Quiet hours (no notifications during this time) */
  quietHours?: {
    enabled: boolean;
    startHour: number; // 0-23
    endHour: number;   // 0-23
    timezone: string;
  };
}

// ============================================================================
// Alert History and Query
// ============================================================================

/** Query parameters for searching alerts */
export interface AlertQuery {
  /** Filter by alert type */
  type?: AlertType;
  /** Filter by severity */
  severity?: AlertSeverity;
  /** Filter by status */
  status?: AlertStatus;
  /** Filter by application ID */
  appId?: string;
  /** Filter by user ID */
  userId?: string;
  /** Filter by agent ID */
  agentId?: string;
  /** Filter alerts after this timestamp */
  startTime?: string;
  /** Filter alerts before this timestamp */
  endTime?: string;
  /** Search in title and message */
  search?: string;
  /** Page number (1-indexed) */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Sort field */
  sortBy?: 'timestamp' | 'severity' | 'type';
  /** Sort order */
  sortOrder?: 'asc' | 'desc';
}

/** Paginated alert history result */
export interface AlertHistoryResult {
  /** Alert records */
  alerts: Alert[];
  /** Total count of matching alerts */
  total: number;
  /** Current page number */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total pages */
  totalPages: number;
}

// ============================================================================
// Alert Statistics
// ============================================================================

/** Statistics about alerts */
export interface AlertStats {
  /** Total alerts in the time period */
  total: number;
  /** Count by type */
  byType: Record<AlertType, number>;
  /** Count by severity */
  bySeverity: Record<AlertSeverity, number>;
  /** Count by status */
  byStatus: Record<AlertStatus, number>;
  /** Count of active alerts */
  activeCount: number;
  /** Average time to acknowledge (in seconds) */
  avgAckTimeSeconds?: number;
  /** Average time to resolve (in seconds) */
  avgResolveTimeSeconds?: number;
}

// ============================================================================
// Default Configurations
// ============================================================================

/** Default alert rules */
export const DEFAULT_ALERT_RULES: AlertRule[] = [
  {
    id: 'high_risk_event',
    type: 'risk_event',
    name: 'High Risk Event',
    description: 'Triggers when a high-risk detection event occurs',
    threshold: 1, // Any high-risk event
    enabled: true,
    channels: [{ type: 'dashboard', enabled: true, config: { showPopup: true, playSound: true } }],
    cooldownSeconds: 60,
    conditions: [{ field: 'riskLevel', operator: 'eq', value: 'high_risk' }],
  },
  {
    id: 'quota_warning_80',
    type: 'quota_warning',
    name: 'Quota Warning (80%)',
    description: 'Triggers when quota usage reaches 80%',
    threshold: 80,
    enabled: true,
    channels: [{ type: 'dashboard', enabled: true, config: { showPopup: true, playSound: false } }],
    cooldownSeconds: 3600, // 1 hour
  },
  {
    id: 'quota_warning_90',
    type: 'quota_warning',
    name: 'Quota Warning (90%)',
    description: 'Triggers when quota usage reaches 90%',
    threshold: 90,
    enabled: true,
    channels: [{ type: 'dashboard', enabled: true, config: { showPopup: true, playSound: true } }],
    cooldownSeconds: 3600,
  },
  {
    id: 'quota_exceeded',
    type: 'quota_exceeded',
    name: 'Quota Exceeded',
    description: 'Triggers when quota limit is exceeded',
    threshold: 100,
    enabled: true,
    channels: [{ type: 'dashboard', enabled: true, config: { showPopup: true, playSound: true } }],
    cooldownSeconds: 0, // Immediate notification
  },
  {
    id: 'anomaly_high_risk_burst',
    type: 'anomaly',
    name: 'High Risk Burst',
    description: 'Triggers when multiple high-risk events occur in a short time',
    threshold: 5, // 5 high-risk events
    enabled: true,
    channels: [{ type: 'dashboard', enabled: true, config: { showPopup: true, playSound: true } }],
    cooldownSeconds: 300, // 5 minutes
    conditions: [{ field: 'anomalyType', operator: 'eq', value: 'high_risk_burst' }],
  },
];

/** Default alert settings */
export const DEFAULT_ALERT_SETTINGS: AlertSettings = {
  enabled: true,
  defaultCooldownSeconds: 300,
  maxHistorySize: 1000,
  enableDigest: false,
  digestFrequencyHours: 24,
};

/** Create a default alert configuration */
export function createDefaultAlertConfiguration(appId?: string, userId?: string): AlertConfiguration {
  const now = new Date().toISOString();
  return {
    id: `alert-config-${Date.now()}`,
    appId,
    userId,
    rules: DEFAULT_ALERT_RULES,
    channels: [
      { type: 'dashboard', enabled: true, config: { showPopup: true, playSound: true, autoDismissSeconds: 10 } },
    ],
    settings: DEFAULT_ALERT_SETTINGS,
    createdAt: now,
    updatedAt: now,
  };
}