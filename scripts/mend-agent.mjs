#!/usr/bin/env node
import { query } from '@anthropic-ai/claude-agent-sdk';

const flags = process.argv.slice(2).join(' ').trim()
  || '--jira=none --scope=all';

const result = query({
  prompt: `/mend ${flags}`,
  options: {
    systemPrompt: { type: 'preset', preset: 'claude_code' },
    pathToClaudeCodeExecutable: process.env.CLAUDE_CLI_PATH || 'claude',
    settingSources: ['project'],
    permissionMode: 'bypassPermissions',
    maxTurns: 60,
    cwd: process.cwd(),
  },
});

let denials = 0;
let isError = false;

for await (const event of result) {
  process.stdout.write(JSON.stringify(event) + '\n');
  if (event.type === 'result') {
    denials = event.permission_denials_count ?? 0;
    isError = event.is_error === true;
  }
}

if (isError) {
  console.error('::error::Claude returned is_error=true');
  process.exit(1);
}
if (denials > 0) {
  console.error(`::error::Claude was denied ${denials} tool call(s) — /mend skill did not complete.`);
  process.exit(1);
}
