import { createGatewayServer } from './server.ts';
import { makeLogger } from '../shared/log.ts';

const log = makeLogger('gateway');

const { server, port, tls } = createGatewayServer();
const scheme = tls ? 'https' : 'http';

server.listen(port, () => {
  log.info(`agentzt-gateway listening on ${scheme}://localhost:${port}`);
  log.info(`  token endpoint   POST /v1/token`);
  log.info(`  model proxy      POST /v1/messages`);
  log.info(`  tool proxy       POST /v1/tools/:name`);
  log.info(`  public keys      GET  /.well-known/agentzt-jwks`);
});

function shutdown(sig: string) {
  log.info(`received ${sig}, shutting down`);
  server.close(() => process.exit(0));
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
