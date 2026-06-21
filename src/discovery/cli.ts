// Agent Discovery CLI
// Command-line interface for agent discovery operations.

import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { DiscoveryConfig, DiscoveryResult, EDRProviderConfig, AgentSignature } from './types.ts';
import { createDiscoveryEngine, DiscoveryEngine } from './engine.ts';
import { createCrowdStrikeProvider } from './crowdstrike.ts';
import { createDefenderProvider } from './defender.ts';
import { createLocalFileProvider } from './local.ts';

/** CLI configuration file path */
const CONFIG_FILE = '.aad/config.json';

/** Default configuration */
const DEFAULT_CONFIG: DiscoveryConfig = {
  providers: [
    {
      type: 'local',
      enabled: true,
      logDir: './logs',
    },
  ],
  signatureDirs: ['./signatures'],
  timeRangeHours: 24,
  minConfidence: 50,
  includeLowRisk: true,
  outputFormat: 'table',
  dashboardPort: 3456,
};

/** Parse command-line arguments */
function parseArgs(args: string[]): Record<string, string | boolean> {
  const result: Record<string, string | boolean> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg && arg.startsWith('--')) {
      const key = arg.slice(2);
      const nextArg = args[i + 1];

      if (nextArg && !nextArg.startsWith('--') && !nextArg.startsWith('-')) {
        result[key] = nextArg;
        i++;
      } else {
        result[key] = true;
      }
    } else if (arg && arg.startsWith('-')) {
      const key = arg.slice(1);
      result[key] = true;
    }
  }

  return result;
}

/** Get flag value from parsed args */
function getFlag(args: Record<string, string | boolean>, name: string): string | undefined {
  const value = args[name];
  return typeof value === 'string' ? value : undefined;
}

/** Check if flag is set */
function isFlagSet(args: Record<string, string | boolean>, name: string): boolean {
  return args[name] === true;
}

/** Show usage information */
function showUsage(): void {
  console.log(`
aad - Agent Discovery Tool

Usage:
  aad <command> [options]

Commands:
  init        Initialize configuration file
  scan        Execute agent discovery scan
  dashboard   Start web dashboard
  config      Show current configuration
  signatures  List loaded signatures
  providers   List configured providers
  help        Show this help message

Options:
  --config <path>      Configuration file path (default: .aad/config.json)
  --output <format>    Output format: json, csv, table (default: table)
  --time-range <hours> Time range for scan (default: 24)
  --min-confidence <n> Minimum confidence threshold (default: 50)
  --no-low-risk        Exclude low-risk agents
  --save <path>        Save results to file

Examples:
  aad init
  aad scan --output json --save results.json
  aad dashboard --port 8080
  aad config

Environment Variables:
  CROWDSTRIKE_CLIENT_ID      CrowdStrike API client ID
  CROWDSTRIKE_CLIENT_SECRET  CrowdStrike API client secret
  AZURE_CLIENT_ID            Microsoft Defender client ID
  AZURE_CLIENT_SECRET        Microsoft Defender client secret
  AGENT_DISCOVERY_LOG_DIR    Local log directory path
`);
}

/** Initialize configuration */
async function cmdInit(args: Record<string, string | boolean>): Promise<void> {
  const configPath = getFlag(args, 'config') || CONFIG_FILE;
  const absolutePath = resolve(configPath);

  // Create directory if needed
  const dir = resolve(absolutePath, '..');
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  // Check if config already exists
  if (existsSync(absolutePath) && !isFlagSet(args, 'force')) {
    console.log(`Configuration file already exists: ${absolutePath}`);
    console.log('Use --force to overwrite.');
    return;
  }

  // Create default configuration
  const config: DiscoveryConfig = {
    ...DEFAULT_CONFIG,
    // Add example CrowdStrike config (disabled)
    providers: [
      ...DEFAULT_CONFIG.providers,
      {
        type: 'crowdstrike',
        enabled: false,
        apiUrl: 'https://api.crowdstrike.com',
        clientIdEnv: 'CROWDSTRIKE_CLIENT_ID',
        clientSecretEnv: 'CROWDSTRIKE_CLIENT_SECRET',
      },
      {
        type: 'defender',
        enabled: false,
        tenantId: 'your-tenant-id',
        clientIdEnv: 'AZURE_CLIENT_ID',
        clientSecretEnv: 'AZURE_CLIENT_SECRET',
      },
    ],
  };

  // Write configuration
  writeFileSync(absolutePath, JSON.stringify(config, null, 2));
  console.log(`Configuration file created: ${absolutePath}`);
  console.log('\nEdit the configuration to enable EDR providers:');
  console.log('  - Set enabled: true for CrowdStrike or Defender');
  console.log('  - Set environment variables for API credentials');
  console.log('\nThen run:');
  console.log('  aad scan');
}

/** Execute scan */
async function cmdScan(args: Record<string, string | boolean>): Promise<void> {
  const configPath = getFlag(args, 'config') || CONFIG_FILE;
  const outputPath = getFlag(args, 'output') || 'table';
  const savePath = getFlag(args, 'save');
  const timeRange = parseInt(getFlag(args, 'time-range') || '24', 10);
  const minConfidence = parseInt(getFlag(args, 'min-confidence') || '50', 10);
  const includeLowRisk = !isFlagSet(args, 'no-low-risk');

  // Load configuration
  const config = loadConfig(configPath);

  // Override with CLI options
  const scanConfig: DiscoveryConfig = {
    ...config,
    timeRangeHours: timeRange,
    minConfidence,
    includeLowRisk,
    outputFormat: outputPath as 'json' | 'csv' | 'table',
  };

  console.log('Starting agent discovery scan...');
  console.log(`Time range: ${timeRange} hours`);
  console.log(`Minimum confidence: ${minConfidence}%`);
  console.log(`Include low-risk: ${includeLowRisk}`);

  // Create engine and run scan
  const engine = createDiscoveryEngine(scanConfig);

  try {
    const result = await engine.scan();

    // Display results
    displayResults(result, scanConfig.outputFormat);

    // Save results if requested
    if (savePath) {
      saveResults(result, savePath);
    }
  } catch (error) {
    console.error('Scan failed:', error instanceof Error ? error.message : 'Unknown error');
  } finally {
    await engine.dispose();
  }
}

/** Start dashboard */
async function cmdDashboard(args: Record<string, string | boolean>): Promise<void> {
  const configPath = getFlag(args, 'config') || CONFIG_FILE;
  const port = parseInt(getFlag(args, 'port') || '3456', 10);

  // Load configuration
  const config = loadConfig(configPath);
  config.dashboardPort = port;

  console.log(`Starting Agent Discovery Dashboard on port ${port}...`);
  console.log(`Open http://localhost:${port} in your browser.`);
  console.log('\nPress Ctrl+C to stop the dashboard.');

  // Create engine
  const engine = createDiscoveryEngine(config);

  try {
    // Start simple HTTP server for dashboard
    await startDashboardServer(engine, port);
  } catch (error) {
    console.error('Dashboard failed:', error instanceof Error ? error.message : 'Unknown error');
  }
}

/** Show configuration */
function cmdConfig(args: Record<string, string | boolean>): void {
  const configPath = getFlag(args, 'config') || CONFIG_FILE;

  if (!existsSync(resolve(configPath))) {
    console.log('Configuration file not found. Run `aad init` to create one.');
    return;
  }

  const config = loadConfig(configPath);
  console.log('Current Configuration:');
  console.log(JSON.stringify(config, null, 2));
}

/** List signatures */
async function cmdSignatures(args: Record<string, string | boolean>): Promise<void> {
  const configPath = getFlag(args, 'config') || CONFIG_FILE;
  const config = loadConfig(configPath);

  const engine = createDiscoveryEngine(config);
  const signatures = engine.getSignatures();

  console.log(`Loaded ${signatures.length} signatures:\n`);

  // Group by type
  const byType: Record<string, AgentSignature[]> = {
    AUTONOMOUS: [],
    ASSISTANT: [],
    WORKFLOW: [],
  };

  for (const sig of signatures) {
    const typeArray = byType[sig.type];
    if (typeArray) {
      typeArray.push(sig);
    }
  }

  for (const [type, sigs] of Object.entries(byType)) {
    console.log(`\n${type} (${sigs.length}):`);
    for (const sig of sigs) {
      console.log(`  - ${sig.name} (risk: ${sig.riskLevel}, confidence: ${sig.confidence}%)`);
      console.log(`    ID: ${sig.id}`);
    }
  }
}

/** List providers */
async function cmdProviders(args: Record<string, string | boolean>): Promise<void> {
  const configPath = getFlag(args, 'config') || CONFIG_FILE;
  const config = loadConfig(configPath);

  console.log('Configured EDR Providers:\n');

  for (const providerConfig of config.providers) {
    const status = providerConfig.enabled ? 'enabled' : 'disabled';
    console.log(`${providerConfig.type}: ${status}`);

    // Test configuration
    let configured = false;
    try {
      switch (providerConfig.type) {
        case 'crowdstrike':
          const cs = createCrowdStrikeProvider(providerConfig);
          configured = await cs.isConfigured();
          break;
        case 'defender':
          const def = createDefenderProvider(providerConfig);
          configured = await def.isConfigured();
          break;
        case 'local':
          const local = createLocalFileProvider(providerConfig);
          configured = await local.isConfigured();
          break;
      }
    } catch {
      configured = false;
    }

    console.log(`  Configured: ${configured ? 'yes' : 'no'}`);
    if (providerConfig.apiUrl) {
      console.log(`  API URL: ${providerConfig.apiUrl}`);
    }
    if (providerConfig.tenantId) {
      console.log(`  Tenant ID: ${providerConfig.tenantId}`);
    }
    if (providerConfig.logDir) {
      console.log(`  Log Dir: ${providerConfig.logDir}`);
    }
    console.log();
  }
}

/** Load configuration from file */
function loadConfig(path: string): DiscoveryConfig {
  const absolutePath = resolve(path);

  if (!existsSync(absolutePath)) {
    console.warn(`Configuration file not found: ${absolutePath}`);
    console.warn('Using default configuration.');
    return DEFAULT_CONFIG;
  }

  try {
    const content = require('fs').readFileSync(absolutePath, 'utf8');
    return JSON.parse(content) as DiscoveryConfig;
  } catch (error) {
    console.error(`Failed to load configuration: ${error}`);
    return DEFAULT_CONFIG;
  }
}

/** Display scan results */
function displayResults(result: DiscoveryResult, format: string): void {
  console.log('\n=== Agent Discovery Results ===');
  console.log(`Scan ID: ${result.scanId}`);
  console.log(`Duration: ${result.startTime} to ${result.endTime}`);
  console.log(`Total Agents Detected: ${result.totalAgents}`);
  console.log(`Sources: ${result.sources.join(', ')}`);

  if (result.errors.length > 0) {
    console.log('\nErrors:');
    for (const error of result.errors) {
      console.log(`  - ${error.source}: ${error.message}`);
    }
  }

  console.log('\nBy Type:');
  console.log(`  AUTONOMOUS: ${result.byType.AUTONOMOUS}`);
  console.log(`  ASSISTANT: ${result.byType.ASSISTANT}`);
  console.log(`  WORKFLOW: ${result.byType.WORKFLOW}`);

  console.log('\nBy Risk Level:');
  console.log(`  Critical: ${result.byRiskLevel.critical}`);
  console.log(`  High: ${result.byRiskLevel.high}`);
  console.log(`  Medium: ${result.byRiskLevel.medium}`);
  console.log(`  Low: ${result.byRiskLevel.low}`);

  if (format === 'table' && result.agents.length > 0) {
    console.log('\nDetected Agents:');
    console.log('-'.repeat(80));

    for (const agent of result.agents) {
      console.log(`\n${agent.name} (${agent.type})`);
      console.log(`  ID: ${agent.agentId}`);
      console.log(`  Endpoint: ${agent.endpoint}`);
      console.log(`  User: ${agent.user || 'unknown'}`);
      console.log(`  Risk Level: ${agent.riskLevel}`);
      console.log(`  Confidence: ${agent.confidence}%`);
      console.log(`  Last Activity: ${agent.lastActivity}`);
      if (agent.process) {
        console.log(`  Process: ${agent.process.name} (PID: ${agent.process.pid})`);
        if (agent.process.commandLine) {
          console.log(`  Command: ${agent.process.commandLine.slice(0, 100)}...`);
        }
      }
      if (agent.networkEndpoints && agent.networkEndpoints.length > 0) {
        console.log(`  Network Endpoints: ${agent.networkEndpoints.map((e) => e.domain || e.ip).join(', ')}`);
      }
    }
  }

  if (format === 'json') {
    console.log('\nJSON Output:');
    console.log(JSON.stringify(result, null, 2));
  }

  if (format === 'csv') {
    console.log('\nCSV Output:');
    console.log('AgentID,Name,Type,Endpoint,User,RiskLevel,Confidence,LastActivity');
    for (const agent of result.agents) {
      console.log(
        `${agent.agentId},${agent.name},${agent.type},${agent.endpoint},${agent.user || ''},${agent.riskLevel},${agent.confidence},${agent.lastActivity}`
      );
    }
  }
}

/** Save results to file */
function saveResults(result: DiscoveryResult, path: string): void {
  const absolutePath = resolve(path);
  writeFileSync(absolutePath, JSON.stringify(result, null, 2));
  console.log(`\nResults saved to: ${absolutePath}`);
}

/** Start simple dashboard HTTP server */
async function startDashboardServer(engine: DiscoveryEngine, port: number): Promise<void> {
  // Simple HTTP server for dashboard
  // In production, this would be a full Express/Fastify server

  const http = await import('node:http');

  const server = http.createServer(async (req, res) => {
    const url = req.url || '/';

    if (url === '/' || url === '/index.html') {
      // Serve dashboard HTML
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(getDashboardHtml());
    } else if (url === '/api/scan') {
      // Run scan and return results
      try {
        const result = await engine.scan();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }));
      }
    } else if (url === '/api/signatures') {
      // Return signatures
      const signatures = engine.getSignatures();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(signatures));
    } else if (url === '/api/providers') {
      // Return providers
      const providerList = engine.getProviders();
      const providers = await Promise.all(providerList.map(async (p) => ({
        name: p.name,
        type: p.type,
        configured: await p.isConfigured(),
      })));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(providers));
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  });

  server.listen(port, () => {
    console.log(`Dashboard server started on port ${port}`);
  });

  // Keep server running
  return new Promise<void>((resolve) => {
    server.on('close', resolve);
  });
}

/** Get dashboard HTML */
function getDashboardHtml(): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agent Discovery Dashboard</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      margin: 0;
      padding: 20px;
      background: #f5f5f5;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    h1 {
      color: #333;
      margin-bottom: 20px;
    }
    .card {
      background: white;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
    }
    .stat-item {
      text-align: center;
    }
    .stat-value {
      font-size: 2em;
      font-weight: bold;
      color: #2196F3;
    }
    .stat-label {
      color: #666;
    }
    .agent-list {
      margin-top: 20px;
    }
    .agent-item {
      padding: 10px;
      border-bottom: 1px solid #eee;
    }
    .agent-item:last-child {
      border-bottom: none;
    }
    .agent-name {
      font-weight: bold;
    }
    .agent-type {
      color: #666;
      font-size: 0.9em;
    }
    .risk-critical { color: #f44336; }
    .risk-high { color: #ff9800; }
    .risk-medium { color: #ffc107; }
    .risk-low { color: #4caf50; }
    .scan-btn {
      background: #2196F3;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1em;
    }
    .scan-btn:hover {
      background: #1976D2;
    }
    .loading {
      text-align: center;
      padding: 40px;
      color: #666;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Agent Discovery Dashboard</h1>
    
    <div class="card">
      <button class="scan-btn" onclick="runScan()">Run Scan</button>
    </div>
    
    <div class="card">
      <h2>Statistics</h2>
      <div class="stats" id="stats">
        <div class="stat-item">
          <div class="stat-value" id="total">-</div>
          <div class="stat-label">Total Agents</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" id="autonomous">-</div>
          <div class="stat-label">Autonomous</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" id="assistant">-</div>
          <div class="stat-label">Assistant</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" id="workflow">-</div>
          <div class="stat-label">Workflow</div>
        </div>
      </div>
    </div>
    
    <div class="card">
      <h2>Detected Agents</h2>
      <div class="agent-list" id="agents">
        <div class="loading">Click "Run Scan" to discover agents</div>
      </div>
    </div>
  </div>
  
  <script>
    async function runScan() {
      const agentsDiv = document.getElementById('agents');
      agentsDiv.innerHTML = '<div class="loading">Scanning...</div>';
      
      try {
        const response = await fetch('/api/scan');
        const result = await response.json();
        
        // Update stats
        document.getElementById('total').textContent = result.totalAgents;
        document.getElementById('autonomous').textContent = result.byType.AUTONOMOUS;
        document.getElementById('assistant').textContent = result.byType.ASSISTANT;
        document.getElementById('workflow').textContent = result.byType.WORKFLOW;
        
        // Update agent list
        if (result.agents.length === 0) {
          agentsDiv.innerHTML = '<div class="loading">No agents detected</div>';
        } else {
          agentsDiv.innerHTML = result.agents.map(agent => {
            const riskClass = 'risk-' + agent.riskLevel;
            return '<div class="agent-item">' +
              '<span class="agent-name">' + agent.name + '</span> ' +
              '<span class="agent-type">(' + agent.type + ')</span> ' +
              '<span class="' + riskClass + '">' + agent.riskLevel.toUpperCase() + '</span> ' +
              '<br><small>Endpoint: ' + agent.endpoint + ' | Confidence: ' + agent.confidence + '%</small>' +
            '</div>';
          }).join('');
        }
      } catch (error) {
        agentsDiv.innerHTML = '<div class="loading">Error: ' + error.message + '</div>';
      }
    }
  </script>
</body>
</html>
`;
}

/** Main CLI entry point */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const parsedArgs = parseArgs(args);

  const [command] = args;

  switch (command) {
    case 'init':
      await cmdInit(parsedArgs);
      break;
    case 'scan':
      await cmdScan(parsedArgs);
      break;
    case 'dashboard':
      await cmdDashboard(parsedArgs);
      break;
    case 'config':
      cmdConfig(parsedArgs);
      break;
    case 'signatures':
      await cmdSignatures(parsedArgs);
      break;
    case 'providers':
      await cmdProviders(parsedArgs);
      break;
    case 'help':
    case '--help':
    case '-h':
      showUsage();
      break;
    default:
      if (!command) {
        showUsage();
      } else {
        console.error(`Unknown command: ${command}`);
        showUsage();
        process.exit(1);
      }
  }
}

// Run CLI
main().catch((error) => {
  console.error('CLI error:', error);
  process.exit(1);
});