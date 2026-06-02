// Minimal structured console logger. Colorized when stdout is a TTY.
const isTTY = process.stdout.isTTY;
const c = (code: string, s: string) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);

const dim = (s: string) => c('2', s);
const red = (s: string) => c('31', s);
const green = (s: string) => c('32', s);
const yellow = (s: string) => c('33', s);
const cyan = (s: string) => c('36', s);

function ts(): string {
  return dim(new Date().toISOString());
}

export function makeLogger(component: string) {
  const tag = cyan(`[${component}]`);
  return {
    info: (msg: string, ...rest: unknown[]) =>
      console.log(`${ts()} ${tag} ${msg}`, ...rest),
    warn: (msg: string, ...rest: unknown[]) =>
      console.warn(`${ts()} ${tag} ${yellow('WARN')} ${msg}`, ...rest),
    error: (msg: string, ...rest: unknown[]) =>
      console.error(`${ts()} ${tag} ${red('ERROR')} ${msg}`, ...rest),
    allow: (msg: string) => console.log(`${ts()} ${tag} ${green('ALLOW')} ${msg}`),
    deny: (msg: string) => console.log(`${ts()} ${tag} ${red('DENY')}  ${msg}`),
  };
}

export type Logger = ReturnType<typeof makeLogger>;
