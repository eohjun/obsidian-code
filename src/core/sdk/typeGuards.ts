/**
 * Type guards for SDK transformer events and hook inputs.
 */

import type { StreamChunk } from '../types';
import type { SessionInitEvent, TransformEvent } from './types';

/**
 * Type guard to check if an event is a session init event
 */
export function isSessionInitEvent(event: TransformEvent): event is SessionInitEvent {
  return event.type === 'session_init';
}

/**
 * Type guard to check if an event is a stream chunk
 */
export function isStreamChunk(event: TransformEvent): event is StreamChunk {
  return event.type !== 'session_init';
}

// ============================================
// Hook Input Type Guards
// ============================================

/** Base hook input structure */
export interface HookToolInput {
  tool_name: string;
  tool_input: Record<string, unknown>;
}

/** Bash tool hook input */
export interface BashHookInput extends HookToolInput {
  tool_name: 'Bash';
  tool_input: {
    command?: string;
    [key: string]: unknown;
  };
}

/** File tool hook input */
export interface FileHookInput extends HookToolInput {
  tool_input: {
    file_path?: string;
    path?: string;
    [key: string]: unknown;
  };
}

/**
 * Type guard to check if input is a valid hook tool input
 */
export function isHookToolInput(input: unknown): input is HookToolInput {
  if (typeof input !== 'object' || input === null) {
    return false;
  }
  const obj = input as Record<string, unknown>;
  return (
    typeof obj.tool_name === 'string' &&
    typeof obj.tool_input === 'object' &&
    obj.tool_input !== null
  );
}

/**
 * Type guard to check if input is a Bash hook input
 */
export function isBashHookInput(input: unknown): input is BashHookInput {
  if (!isHookToolInput(input)) {
    return false;
  }
  return input.tool_name === 'Bash';
}

/**
 * Type guard to check if input is a file-related hook input
 */
export function isFileHookInput(input: unknown): input is FileHookInput {
  if (!isHookToolInput(input)) {
    return false;
  }
  const toolInput = input.tool_input;
  return (
    typeof toolInput.file_path === 'string' ||
    typeof toolInput.path === 'string'
  );
}

/**
 * Safely extract command from hook input
 */
export function extractBashCommand(input: unknown): string {
  if (!isBashHookInput(input)) {
    return '';
  }
  return typeof input.tool_input.command === 'string' ? input.tool_input.command : '';
}

/**
 * Safely extract tool name from hook input
 */
export function extractToolName(input: unknown): string {
  if (!isHookToolInput(input)) {
    return '';
  }
  return input.tool_name;
}

/**
 * Safely extract tool input object from hook input
 */
export function extractToolInput(input: unknown): Record<string, unknown> {
  if (!isHookToolInput(input)) {
    return {};
  }
  return input.tool_input;
}
