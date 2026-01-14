/**
 * Security Hooks
 *
 * PreToolUse hooks for enforcing blocklist and vault restriction.
 */

import type { HookCallbackMatcher } from '@anthropic-ai/claude-agent-sdk';

import type { PathAccessType } from '../../utils/path';
import { extractBashCommand, extractToolInput, extractToolName, isHookToolInput } from '../sdk/typeGuards';
import type { PathCheckContext } from '../security/BashPathValidator';
import { findBashCommandPathViolation, findDangerousConstruct } from '../security/BashPathValidator';
import { isCommandBlocked } from '../security/BlocklistChecker';
import { getPathFromToolInput } from '../tools/toolInput';
import { isEditTool, isFileTool, TOOL_BASH } from '../tools/toolNames';
import { getBashToolBlockedCommands, type PlatformBlockedCommands } from '../types';

/** Context for blocklist checking. */
export interface BlocklistContext {
  blockedCommands: PlatformBlockedCommands;
  enableBlocklist: boolean;
}

/** Context for vault restriction checking. */
export interface VaultRestrictionContext {
  getPathAccessType: (filePath: string) => PathAccessType;
}

/**
 * Create a PreToolUse hook to enforce the command blocklist.
 */
export function createBlocklistHook(getContext: () => BlocklistContext): HookCallbackMatcher {
  return {
    matcher: TOOL_BASH,
    hooks: [
      async (hookInput) => {
        if (!isHookToolInput(hookInput)) {
          return { continue: true };
        }
        const command = extractBashCommand(hookInput);
        const context = getContext();

        const bashToolCommands = getBashToolBlockedCommands(context.blockedCommands);
        if (isCommandBlocked(command, bashToolCommands, context.enableBlocklist)) {
          return {
            continue: false,
            hookSpecificOutput: {
              hookEventName: 'PreToolUse' as const,
              permissionDecision: 'deny' as const,
              permissionDecisionReason: `Command blocked by blocklist: ${command}`,
            },
          };
        }

        return { continue: true };
      },
    ],
  };
}

/**
 * Create a PreToolUse hook to restrict file access to the vault.
 */
export function createVaultRestrictionHook(context: VaultRestrictionContext): HookCallbackMatcher {
  return {
    hooks: [
      async (hookInput) => {
        if (!isHookToolInput(hookInput)) {
          return { continue: true };
        }

        const toolName = extractToolName(hookInput);

        // Bash: inspect command for dangerous constructs and paths that escape the vault
        if (toolName === TOOL_BASH) {
          const command = extractBashCommand(hookInput);

          // First, check for dangerous bash constructs that could bypass security
          const dangerousConstruct = findDangerousConstruct(command);
          if (dangerousConstruct) {
            let reason: string;
            switch (dangerousConstruct.type) {
              case 'command_substitution':
                reason = `Access denied: Command substitution "${dangerousConstruct.pattern}" is not allowed as it could execute arbitrary code.`;
                break;
              case 'backtick_substitution':
                reason = `Access denied: Backtick substitution "${dangerousConstruct.pattern}" is not allowed as it could execute arbitrary code.`;
                break;
              case 'dangerous_builtin':
                reason = `Access denied: The "${dangerousConstruct.command}" command is not allowed as it could execute arbitrary code.`;
                break;
              case 'hex_escape':
                reason = `Access denied: Hex/octal escape sequences "${dangerousConstruct.pattern}" are not allowed as they could obfuscate malicious paths.`;
                break;
              case 'process_substitution':
                reason = `Access denied: Process substitution "${dangerousConstruct.pattern}" is not allowed as it could execute arbitrary code.`;
                break;
            }
            return {
              continue: false,
              hookSpecificOutput: {
                hookEventName: 'PreToolUse' as const,
                permissionDecision: 'deny' as const,
                permissionDecisionReason: reason,
              },
            };
          }

          // Then check for path violations
          const pathCheckContext: PathCheckContext = {
            getPathAccessType: (p) => context.getPathAccessType(p),
          };
          const violation = findBashCommandPathViolation(command, pathCheckContext);
          if (violation) {
            const reason =
              violation.type === 'export_path_read'
                ? `Access denied: Command path "${violation.path}" is in an allowed export directory, but export paths are write-only.`
                : `Access denied: Command path "${violation.path}" is outside the vault. Agent is restricted to vault directory only.`;
            return {
              continue: false,
              hookSpecificOutput: {
                hookEventName: 'PreToolUse' as const,
                permissionDecision: 'deny' as const,
                permissionDecisionReason: reason,
              },
            };
          }
          return { continue: true };
        }

        // Skip if not a file-related tool
        if (!isFileTool(toolName)) {
          return { continue: true };
        }

        // Get the path from tool input
        const toolInput = extractToolInput(hookInput);
        const filePath = getPathFromToolInput(toolName, toolInput);

        if (filePath) {
          const accessType = context.getPathAccessType(filePath);

          // Allow full access to vault, readwrite, and context paths
          if (accessType === 'vault' || accessType === 'readwrite' || accessType === 'context') {
            return { continue: true };
          }

          // Export paths are write-only
          if (isEditTool(toolName) && accessType === 'export') {
            return { continue: true };
          }

          if (!isEditTool(toolName) && accessType === 'export') {
            return {
              continue: false,
              hookSpecificOutput: {
                hookEventName: 'PreToolUse' as const,
                permissionDecision: 'deny' as const,
                permissionDecisionReason: `Access denied: Path "${filePath}" is in an allowed export directory, but export paths are write-only.`,
              },
            };
          }

          return {
            continue: false,
            hookSpecificOutput: {
              hookEventName: 'PreToolUse' as const,
              permissionDecision: 'deny' as const,
              permissionDecisionReason: `Access denied: Path "${filePath}" is outside the vault. Agent is restricted to vault directory only.`,
            },
          };
        }

        return { continue: true };
      },
    ],
  };
}
