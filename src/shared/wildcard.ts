export function wildcardToRegex(pattern: string): RegExp {
  // Treat "/" as the model namespace boundary. Hyphens remain valid within one
  // model name segment (for example claude-sonnet-4-6 and deepseek-coder).
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return new RegExp(`^${escaped}$`);
}
