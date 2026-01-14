/**
 * Blocklist Checker
 *
 * Checks bash commands against user-defined blocklist patterns.
 * Patterns are treated as case-insensitive regex with fallback to substring match.
 *
 * Security Note: This blocklist is a defense-in-depth measure, not primary security.
 * It can be bypassed by determined attackers. The primary security is the vault restriction.
 */

import * as path from 'path';

/**
 * Normalize a command by removing common bypass techniques.
 * This helps catch attempts to evade blocklist patterns.
 *
 * @param command - The raw command string
 * @returns Normalized command with bypass attempts removed
 */
export function normalizeCommand(command: string): string {
  let normalized = command;

  // Remove empty quotes that could be used to break patterns
  // e.g., r''m, r""m, r``m -> rm
  normalized = normalized.replace(/''|""|``/g, '');

  // Remove backslash escapes in command names (not in arguments)
  // e.g., r\m -> rm (but preserve backslashes in paths)
  // Only apply to the first word (command name)
  const parts = normalized.split(/\s+/);
  if (parts.length > 0) {
    parts[0] = parts[0].replace(/\\/g, '');
    normalized = parts.join(' ');
  }

  return normalized;
}

/**
 * Extract the base command name from a potentially path-prefixed command.
 * e.g., /usr/bin/rm -> rm, ./script.sh -> script.sh
 *
 * @param commandToken - The first token of a command
 * @returns The base command name
 */
export function extractCommandName(commandToken: string): string {
  // Handle paths like /usr/bin/rm or ./rm
  return path.basename(commandToken);
}

/**
 * Extract all command names from a compound command.
 * Handles pipelines (|), command chains (&&, ||, ;), etc.
 *
 * @param command - The full command string
 * @returns Array of command names found
 */
export function extractAllCommandNames(command: string): string[] {
  const commandNames: string[] = [];

  // Split by common command separators
  const segments = command.split(/\s*(?:\|\||&&|[|;&])\s*/);

  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed) continue;

    // Get the first token (the command)
    const tokens = trimmed.split(/\s+/);
    let cmdToken = tokens[0];

    // Skip common wrappers
    const wrappers = ['sudo', 'env', 'command', 'nohup', 'nice', 'time'];
    let i = 0;
    while (i < tokens.length && wrappers.includes(tokens[i])) {
      i++;
    }
    if (i < tokens.length) {
      cmdToken = tokens[i];
    }

    if (cmdToken) {
      commandNames.push(extractCommandName(cmdToken));
    }
  }

  return commandNames;
}

/**
 * Check if a bash command should be blocked by user-defined patterns.
 * Now includes normalization to prevent common bypass techniques.
 *
 * @param command - The bash command to check
 * @param patterns - Array of blocklist patterns (regex or substring)
 * @param enableBlocklist - Whether blocklist checking is enabled
 * @returns true if the command should be blocked
 */
export function isCommandBlocked(
  command: string,
  patterns: string[],
  enableBlocklist: boolean
): boolean {
  if (!enableBlocklist || !command) {
    return false;
  }

  // Normalize the command to handle bypass attempts
  const normalizedCommand = normalizeCommand(command);

  // Extract all command names for word-boundary matching
  const commandNames = extractAllCommandNames(normalizedCommand);

  return patterns.some((pattern) => {
    const patternLower = pattern.toLowerCase().trim();
    if (!patternLower) return false;

    // First, check if the pattern matches any extracted command name exactly
    // This catches /usr/bin/rm when pattern is "rm"
    for (const cmdName of commandNames) {
      if (cmdName.toLowerCase() === patternLower) {
        return true;
      }
    }

    // Determine if pattern is a simple command name (single word, all word characters)
    // vs a complex pattern (contains spaces, special chars, etc.)
    const isSimpleCommand = /^[a-z0-9_-]+$/i.test(patternLower);

    // Then try regex matching on the full normalized command
    try {
      if (isSimpleCommand) {
        // For simple command names, use word boundaries to prevent partial matches
        // This prevents "rm" from matching "format" but allows "rm -rf"
        const hasWordBoundary = pattern.includes('\\b');
        const regexPattern = hasWordBoundary ? pattern : `\\b${pattern}\\b`;
        return new RegExp(regexPattern, 'i').test(normalizedCommand);
      } else {
        // For complex patterns (with spaces, =, etc.), use simpler matching
        // Pattern already has structure that provides implicit boundaries
        return new RegExp(pattern, 'i').test(normalizedCommand);
      }
    } catch {
      // Invalid regex - fall back to simple substring match (case-insensitive)
      return normalizedCommand.toLowerCase().includes(patternLower);
    }
  });
}

/**
 * Validate a blocklist pattern.
 *
 * @param pattern - The pattern to validate
 * @returns Object with isValid flag and optional error message
 */
export function validateBlocklistPattern(pattern: string): { isValid: boolean; error?: string } {
  if (!pattern.trim()) {
    return { isValid: false, error: 'Pattern cannot be empty' };
  }

  try {
    new RegExp(pattern, 'i');
    return { isValid: true };
  } catch (e) {
    // Pattern is invalid as regex but will work as substring match
    return {
      isValid: true,
      error: `Invalid regex, will use substring match: ${e instanceof Error ? e.message : 'unknown error'}`,
    };
  }
}
