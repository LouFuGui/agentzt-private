/**
 * WebSocket Alert Service
 * Provides real-time alert notifications to Dashboard clients via WebSocket.
 */

import type { Alert, AlertType, DashboardConfig, AlertDetails } from './types.ts';
import { makeLogger } from '../shared/log.ts';
import type { IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, WebSocket } from 'ws';
import type { RawData } from 'ws';

const log = makeLogger('alert-websocket');

// ============================================================================
// WebSocket Message Types
// ============================================================================

/** Message sent to WebSocket clients */
export interface WebSocketMessage {
  type: 'alert' | 'stats' | 'event' | 'ping' | 'pong' | 'subscribe' | 'unsubscribe';
  payload: unknown;
  timestamp: string;
}

/** Alert message format for Dashboard */
export interface DashboardAlertMessage {
  id: string;
  type: AlertType;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  timestamp: string;
  appId?: string;
  userId?: string;
  agentId?: string;
  details?: Record<string, unknown>;
}

/** Client subscription request */
export interface SubscriptionRequest {
  types?: AlertType[];  // Subscribe to specific alert types
  appId?: string;       // Subscribe to alerts for specific app
  userId?: string;      // Subscribe to alerts for specific user
}

// ============================================================================
// WebSocket Client Connection
// ============================================================================

/** Represents a connected WebSocket client */
interface WebSocketClient {
  /** WebSocket connection */
  ws: WebSocket;
  /** Client ID (generated) */
  clientId: string;
  /** Connection timestamp */
  connectedAt: string;
  /** Subscription filters */
  subscription: SubscriptionRequest;
  /** Last ping timestamp */
  lastPing?: string;
  /** Is connection alive */
  isAlive: boolean;
}

// ============================================================================
// WebSocket Alert Service
// ============================================================================

/**
 * WebSocket server for real-time alert notifications.
 */
export class WebSocketAlertService {
  private wss: WebSocketServer | null = null;
  private clients: Map<string, WebSocketClient> = new Map();
  private pingInterval: NodeJS.Timeout | null = null;
  private pingTimeoutMs: number = 30000; // 30 seconds

  /**
   * Start WebSocket server
   */
  start(port?: number): void {
    if (this.wss) {
      log.warn('WebSocket server already running');
      return;
    }

    this.wss = new WebSocketServer({ port });
    this.setupEventHandlers();
    this.startPingInterval();

    log.info(`WebSocket alert service started on port ${port ?? 'default'}`);
  }

  /**
   * Handle WebSocket upgrade from HTTP server
   */
  handleUpgrade(
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
    callback?: (ws: WebSocket) => void
  ): void {
    if (!this.wss) {
      // Create WebSocket server without specific port (uses existing HTTP server)
      this.wss = new WebSocketServer({ noServer: true });
      this.setupEventHandlers();
      this.startPingInterval();
    }

    this.wss.handleUpgrade(request, socket, head, (ws) => {
      const client = this.registerClient(ws);
      if (callback) callback(ws);
      log.info(`WebSocket client connected: ${client.clientId}`);
    });
  }

  /**
   * Setup WebSocket event handlers
   */
  private setupEventHandlers(): void {
    if (!this.wss) return;

    this.wss.on('connection', (ws) => {
      const client = this.registerClient(ws);

      ws.on('message', (data: RawData) => {
        this.handleMessage(client, data);
      });

      ws.on('close', () => {
        this.unregisterClient(client.clientId);
        log.info(`WebSocket client disconnected: ${client.clientId}`);
      });

      ws.on('error', (error) => {
        log.error(`WebSocket error for client ${client.clientId}: ${error}`);
        this.unregisterClient(client.clientId);
      });

      // Send initial connection message
      this.sendToClient(client, {
        type: 'pong',
        payload: { connected: true, clientId: client.clientId },
        timestamp: new Date().toISOString(),
      });
    });
  }

  /**
   * Register a new WebSocket client
   */
  private registerClient(ws: WebSocket): WebSocketClient {
    const clientId = this.generateClientId();
    const client: WebSocketClient = {
      ws,
      clientId,
      connectedAt: new Date().toISOString(),
      subscription: {},
      isAlive: true,
    };
    this.clients.set(clientId, client);
    return client;
  }

  /**
   * Unregister a WebSocket client
   */
  private unregisterClient(clientId: string): void {
    this.clients.delete(clientId);
  }

  /**
   * Handle incoming message from client
   */
  private handleMessage(client: WebSocketClient, data: RawData): void {
    try {
      const message: WebSocketMessage = JSON.parse(data.toString());

      switch (message.type) {
        case 'ping':
          client.lastPing = message.timestamp;
          client.isAlive = true;
          this.sendToClient(client, {
            type: 'pong',
            payload: { pong: true },
            timestamp: new Date().toISOString(),
          });
          break;

        case 'subscribe':
          this.handleSubscribe(client, message.payload as SubscriptionRequest);
          break;

        case 'unsubscribe':
          this.handleUnsubscribe(client);
          break;

        default:
          log.warn(`Unknown message type from client ${client.clientId}: ${message.type}`);
      }
    } catch (error) {
      log.error(`Failed to parse message from client ${client.clientId}: ${error}`);
    }
  }

  /**
   * Handle subscription request
   */
  private handleSubscribe(client: WebSocketClient, request: SubscriptionRequest): void {
    client.subscription = request;
    log.info(`Client ${client.clientId} subscribed: ${JSON.stringify(request)}`);
    this.sendToClient(client, {
      type: 'subscribe',
      payload: { success: true, subscription: request },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle unsubscribe request
   */
  private handleUnsubscribe(client: WebSocketClient): void {
    client.subscription = {};
    log.info(`Client ${client.clientId} unsubscribed`);
    this.sendToClient(client, {
      type: 'unsubscribe',
      payload: { success: true },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Start ping interval to check client connections
   */
  private startPingInterval(): void {
    this.pingInterval = setInterval(() => {
      this.clients.forEach((client) => {
        if (!client.isAlive) {
          log.warn(`Terminating dead connection: ${client.clientId}`);
          client.ws.terminate();
          this.unregisterClient(client.clientId);
          return;
        }

        client.isAlive = false;
        client.ws.ping();
      });
    }, this.pingTimeoutMs);
  }

  /**
   * Stop WebSocket server
   */
  stop(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }

    if (this.wss) {
      // Close all client connections
      this.clients.forEach((client) => {
        client.ws.close();
      });
      this.clients.clear();

      this.wss.close();
      this.wss = null;
      log.info('WebSocket alert service stopped');
    }
  }

  /**
   * Broadcast alert to all connected clients
   */
  broadcastAlert(alert: Alert, config?: DashboardConfig): void {
    const message: WebSocketMessage = {
      type: 'alert',
      payload: this.formatAlertForDashboard(alert),
      timestamp: new Date().toISOString(),
    };

    this.clients.forEach((client) => {
      if (this.shouldSendToClient(client, alert, config)) {
        this.sendToClient(client, message);
      }
    });

    log.info(`Alert broadcasted to ${this.clients.size} clients: ${alert.id}`);
  }

  /**
   * Send alert to specific client
   */
  sendAlertToClient(clientId: string, alert: Alert): boolean {
    const client = this.clients.get(clientId);
    if (!client) {
      log.warn(`Client not found: ${clientId}`);
      return false;
    }

    const message: WebSocketMessage = {
      type: 'alert',
      payload: this.formatAlertForDashboard(alert),
      timestamp: new Date().toISOString(),
    };

    this.sendToClient(client, message);
    return true;
  }

  /**
   * Check if alert should be sent to client based on subscription
   */
  private shouldSendToClient(
    client: WebSocketClient,
    alert: Alert,
    config?: DashboardConfig
  ): boolean {
    const subscription = client.subscription;

    // Check alert type subscription
    if (subscription.types && subscription.types.length > 0) {
      if (!subscription.types.includes(alert.type)) {
        return false;
      }
    }

    // Check config subscription
    if (config?.subscribedTypes && config.subscribedTypes.length > 0) {
      if (!config.subscribedTypes.includes(alert.type)) {
        return false;
      }
    }

    // Check app subscription
    if (subscription.appId && alert.appId !== subscription.appId) {
      return false;
    }

    // Check user subscription
    if (subscription.userId && alert.userId !== subscription.userId) {
      return false;
    }

    return true;
  }

  /**
   * Format alert for Dashboard display
   */
  private formatAlertForDashboard(alert: Alert): DashboardAlertMessage {
    // Convert AlertDetails to Record<string, unknown>
    const details: Record<string, unknown> = {
      riskLevel: alert.details.riskLevel,
      categories: alert.details.categories,
      score: alert.details.score,
      quotaPercentage: alert.details.quotaPercentage,
      quotaType: alert.details.quotaType,
      anomalyType: alert.details.anomalyType,
      eventCount: alert.details.eventCount,
      timeWindowSeconds: alert.details.timeWindowSeconds,
      eventData: alert.details.eventData,
      metadata: alert.details.metadata,
    };
    
    return {
      id: alert.id,
      type: alert.type,
      title: alert.title,
      message: alert.message,
      severity: alert.severity,
      timestamp: alert.timestamp,
      appId: alert.appId,
      userId: alert.userId,
      agentId: alert.agentId,
      details,
    };
  }

  /**
   * Send message to specific client
   */
  private sendToClient(client: WebSocketClient, message: WebSocketMessage): void {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(message));
    }
  }

  /**
   * Broadcast stats update to all clients
   */
  broadcastStats(stats: unknown): void {
    const message: WebSocketMessage = {
      type: 'stats',
      payload: stats,
      timestamp: new Date().toISOString(),
    };

    this.clients.forEach((client) => {
      this.sendToClient(client, message);
    });
  }

  /**
   * Broadcast event update to all clients
   */
  broadcastEvent(event: unknown): void {
    const message: WebSocketMessage = {
      type: 'event',
      payload: event,
      timestamp: new Date().toISOString(),
    };

    this.clients.forEach((client) => {
      this.sendToClient(client, message);
    });
  }

  /**
   * Get connected client count
   */
  getClientCount(): number {
    return this.clients.size;
  }

  /**
   * Get all connected client IDs
   */
  getClientIds(): string[] {
    return Array.from(this.clients.keys());
  }

  /**
   * Generate unique client ID
   */
  private generateClientId(): string {
    return `client-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }

  /**
   * Check if server is running
   */
  isRunning(): boolean {
    return this.wss !== null;
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

let defaultWebSocketService: WebSocketAlertService | null = null;

/**
 * Get or create the default WebSocket alert service
 */
export function getWebSocketAlertService(): WebSocketAlertService {
  if (!defaultWebSocketService) {
    defaultWebSocketService = new WebSocketAlertService();
  }
  return defaultWebSocketService;
}

/**
 * Reset WebSocket service (for testing)
 */
export function resetWebSocketAlertService(): void {
  if (defaultWebSocketService) {
    defaultWebSocketService.stop();
  }
  defaultWebSocketService = null;
}