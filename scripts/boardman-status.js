#!/usr/bin/env node

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { spawnSync } = require('child_process');
const dotenv = require('dotenv');
const yaml = require('js-yaml');

const cwd = process.cwd();
const platformRoot = path.resolve(cwd, '../../..');
const args = new Set(process.argv.slice(2));

const REQUIRED_ENV = [
  'GITHUB_APP_ID',
  'GITHUB_APP_PRIVATE_KEY',
  'GITHUB_WEBHOOK_SECRET',
  'GITHUB_INSTALLATION_ID',
  'GITHUB_ORG',
  'PLAKY_API_KEY',
  'PLAKY_BASE_URL',
  'PLAKY_WORKSPACE_ID',
  'PLAKY_BOARD_ID',
  'PLAKY_ITEM_GROUP_ID',
  'PLAKY_FIELD_EXTERNAL_KEY_ID',
  'PLAKY_FIELD_GITHUB_URL_ID',
  'PLAKY_FIELD_REPO_ID',
  'PLAKY_FIELD_STATUS_ID',
  'PLAKY_FIELD_PR_URL_ID',
  'PLAKY_FIELD_MERGE_STATE_ID',
  'PLAKY_STATUS_OPEN_VALUE',
  'PLAKY_STATUS_CLOSED_VALUE',
  'PLAKY_MERGE_STATE_OPEN_VALUE',
  'PLAKY_MERGE_STATE_MERGED_VALUE',
  'PLAKY_MERGE_STATE_CLOSED_VALUE',
  'PLAKY_MERGE_STATE_DRAFT_VALUE',
  'ROUTE_SECRET'
];

const OPTIONAL_ENV = [
  'GITHUB_PAT',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_API_TOKEN',
  'OPENAI_API_KEY',
  'OPENAI_MODEL',
  'OPENROUTER_API_KEY',
  'GEMINI_API_KEY',
  'PLAKY_NEEDS_QA_STATUS',
  'PLAKY_IN_QA_STATUS',
  'PLAKY_PR_MERGE_STATUS',
  'PLAKY_FIELD_QA_ASSIGNEE_ID',
  'BOARDMAN_CONFIG_DIR',
  'BOARDMAN_TARGET_ENV',
  'BOARDMAN_GITHUB_AUTH_MODE',
  'BOARDMAN_QUEUE_MODE',
  'BOARDMAN_WEBHOOK_URL',
  'BOARDMAN_SECRETS_ROTATED'
];

const ROTATION_GATE_ENV = [
  'PLAKY_API_KEY',
  'GITHUB_PAT',
  'GITHUB_APP_PRIVATE_KEY',
  'GITHUB_WEBHOOK_SECRET',
  'CLOUDFLARE_API_TOKEN',
  'ROUTE_SECRET',
  'OPENAI_API_KEY',
  'OPENROUTER_API_KEY',
  'GEMINI_API_KEY',
  'JWT_SECRET',
  'INTERNAL_SERVICE_SECRET',
  'REDIS_PASSWORD',
  'POSTGRES_PASSWORD'
];

const SMOKE_FLAGS = [
  ['Issue webhook creates/updates Plaky item', 'BOARDMAN_SMOKE_ISSUE_PASSED'],
  ['Replay webhook creates no duplicate', 'BOARDMAN_SMOKE_REPLAY_PASSED'],
  ['PR linkage updates linked task', 'BOARDMAN_SMOKE_PR_LINKAGE_PASSED'],
  ['Review/comment status update works', 'BOARDMAN_SMOKE_REVIEW_COMMENT_PASSED']
];

function loadEnvFiles() {
  const candidates = [
    path.join(platformRoot, '.env'),
    path.join(platformRoot, '.env.local'),
    path.join(cwd, '.env'),
    path.join(cwd, '.env.local'),
    path.join(cwd, '.env.boardman.production')
  ];

  const loaded = [];
  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    dotenv.config({ path: file, override: false });
    loaded.push(path.relative(cwd, file));
  }
  return loaded;
}

function envValue(name) {
  const value = process.env[name];
  return typeof value === 'string' ? value.trim() : '';
}

function isPlaceholder(value) {
  const normalized = value.trim().toLowerCase();
  return (
    normalized === '' ||
    normalized === '0' ||
    normalized.startsWith('your-') ||
    normalized.includes('replace-me') ||
    normalized.includes('change-me') ||
    normalized.includes('<') ||
    normalized.includes('>')
  );
}

function pass(label, details = '') {
  return { status: 'PASS', label, details };
}

function warn(label, details = '') {
  return { status: 'WARN', label, details };
}

function fail(label, details = '') {
  return { status: 'FAIL', label, details };
}

function runCommand(command, commandArgs) {
  const started = Date.now();
  const result = spawnSync(command, commandArgs, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  });

  return {
    ok: result.status === 0,
    status: result.status,
    durationMs: Date.now() - started,
    output: [result.stdout, result.stderr].filter(Boolean).join('\n').trim()
  };
}

function readYaml(file) {
  try {
    return yaml.load(fs.readFileSync(file, 'utf8')) || {};
  } catch (error) {
    return { __error: error instanceof Error ? error.message : String(error) };
  }
}

function resolveConfigDir() {
  return envValue('BOARDMAN_CONFIG_DIR') || path.join(cwd, 'config');
}

function checkEnv() {
  const requiredMissing = [];
  const requiredPlaceholder = [];

  for (const name of REQUIRED_ENV) {
    const value = envValue(name);
    if (!value) {
      requiredMissing.push(name);
    } else if (isPlaceholder(value)) {
      requiredPlaceholder.push(name);
    }
  }

  const presentOptional = OPTIONAL_ENV.filter((name) => Boolean(envValue(name)));
  const checks = [];

  if (requiredMissing.length === 0 && requiredPlaceholder.length === 0) {
    checks.push(pass('Required Boardman env vars are set'));
  } else {
    checks.push(fail('Required Boardman env vars are not ready', [
      requiredMissing.length ? `missing: ${requiredMissing.join(', ')}` : '',
      requiredPlaceholder.length ? `placeholder: ${requiredPlaceholder.join(', ')}` : ''
    ].filter(Boolean).join('; ')));
  }

  checks.push(
    presentOptional.length
      ? pass('Optional/deployment env vars detected', presentOptional.join(', '))
      : warn('No optional deployment env vars detected', OPTIONAL_ENV.join(', '))
  );

  return checks;
}

function checkRotationGate() {
  const rotationConfirmed = envValue('BOARDMAN_SECRETS_ROTATED') === '1';
  const presentSensitive = ROTATION_GATE_ENV.filter((name) => Boolean(envValue(name)));

  if (rotationConfirmed) {
    return [pass('Secret rotation is confirmed', 'BOARDMAN_SECRETS_ROTATED=1')];
  }

  if (presentSensitive.length > 0) {
    return [fail('Secret rotation is not confirmed', `set BOARDMAN_SECRETS_ROTATED=1 only after rotating: ${presentSensitive.join(', ')}`)];
  }

  return [warn('Secret rotation is not confirmed', 'No sensitive values loaded locally, but exposed credentials must be rotated before deploy')];
}

function checkReposConfig(configDir) {
  const reposFile = path.join(configDir, 'repos.yml');
  const exampleFile = path.join(configDir, 'repos.yml.example');

  if (!fs.existsSync(reposFile)) {
    return [
      fail('repos.yml is missing', fs.existsSync(exampleFile)
        ? `copy ${path.relative(cwd, exampleFile)} to ${path.relative(cwd, reposFile)} and fill real IDs`
        : `expected ${path.relative(cwd, reposFile)}`)
    ];
  }

  const parsed = readYaml(reposFile);
  if (parsed.__error) return [fail('repos.yml cannot be parsed', parsed.__error)];

  const repos = parsed.repos && typeof parsed.repos === 'object' ? parsed.repos : {};
  const entries = Object.entries(repos);
  const invalid = [];

  for (const [repoFullName, entry] of entries) {
    const boardId = String(entry && entry.plaky_board_id !== undefined ? entry.plaky_board_id : '').trim();
    const groupId = String(entry && entry.plaky_group_id !== undefined ? entry.plaky_group_id : '').trim();
    if (!boardId || boardId === '0' || !groupId || groupId === '0') {
      invalid.push(repoFullName);
    }
  }

  if (entries.length === 0) {
    return [fail('repos.yml has no repo mappings', 'add repo -> Plaky board/group IDs')];
  }

  if (invalid.length > 0) {
    return [fail('repos.yml has incomplete Plaky routing', invalid.join(', '))];
  }

  return [pass('repos.yml has repo routing', `${entries.length} repo mapping(s)`)];
}

function checkTeamAssignments(configDir) {
  const teamFile = path.join(configDir, 'team_assignments.yml');
  const exampleFile = path.join(configDir, 'team_assignments.yml.example');

  if (!fs.existsSync(teamFile)) {
    return [
      warn('team_assignments.yml is missing', fs.existsSync(exampleFile)
        ? `copy ${path.relative(cwd, exampleFile)} if QA auto-assignment is in scope`
        : 'QA auto-assignment will be skipped')
    ];
  }

  const parsed = readYaml(teamFile);
  if (parsed.__error) return [fail('team_assignments.yml cannot be parsed', parsed.__error)];

  const assignees = Array.isArray(parsed.qa_assignees) ? parsed.qa_assignees : [];
  const invalid = assignees.filter((entry) => !entry || !entry.plaky_user_id || String(entry.plaky_user_id) === '0');

  if (assignees.length === 0) {
    return [warn('team_assignments.yml has no QA assignees', 'QA auto-assignment will be skipped')];
  }
  if (invalid.length > 0) {
    return [fail('team_assignments.yml has incomplete QA assignees', `${invalid.length} invalid entry/entries`)];
  }
  return [pass('team_assignments.yml has QA assignees', `${assignees.length} assignee(s)`)];
}

function checkDeploymentDecisions() {
  const targetEnv = envValue('BOARDMAN_TARGET_ENV');
  const authMode = envValue('BOARDMAN_GITHUB_AUTH_MODE');
  const queueMode = envValue('BOARDMAN_QUEUE_MODE') || (envValue('KAFKA_BROKERS') ? 'kafka-compatible' : '');
  const webhookUrl = envValue('BOARDMAN_WEBHOOK_URL') || (envValue('EXTERNAL_BRIDGE_BASE_URL') ? `${envValue('EXTERNAL_BRIDGE_BASE_URL').replace(/\/+$/, '')}/webhooks/github` : '');

  return [
    targetEnv ? pass('Target environment selected', targetEnv) : fail('Target environment is not selected', 'set BOARDMAN_TARGET_ENV, e.g. vps-docker-compose'),
    authMode ? pass('GitHub auth mode selected', authMode) : fail('GitHub auth mode is not selected', 'set BOARDMAN_GITHUB_AUTH_MODE, e.g. github-app'),
    queueMode ? pass('Queue mode selected', queueMode) : fail('Queue mode is not selected', 'set BOARDMAN_QUEUE_MODE, e.g. kafka-compatible or redis'),
    webhookUrl ? pass('Webhook URL is set', webhookUrl) : fail('Webhook URL is not set', 'set BOARDMAN_WEBHOOK_URL or EXTERNAL_BRIDGE_BASE_URL')
  ];
}

function requestUrl(url) {
  return new Promise((resolve) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, { timeout: 5000 }, (res) => {
      res.resume();
      resolve(res.statusCode && res.statusCode >= 200 && res.statusCode < 300);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function checkHealth() {
  if (!args.has('--check-health')) {
    return [warn('Health checks not run', 'pass --check-health to verify API and worker endpoints')];
  }

  const apiUrl = envValue('API_HEALTH_URL') || 'http://localhost:5006/health';
  const workerUrl = envValue('WORKER_HEALTH_URL') || 'http://localhost:5007/health';
  const [apiOk, workerOk] = await Promise.all([requestUrl(apiUrl), requestUrl(workerUrl)]);

  return [
    apiOk ? pass('API health endpoint passed', apiUrl) : fail('API health endpoint failed', apiUrl),
    workerOk ? pass('Worker health endpoint passed', workerUrl) : fail('Worker health endpoint failed', workerUrl)
  ];
}

function checkSmokeFlags() {
  return SMOKE_FLAGS.map(([label, name]) => {
    const value = envValue(name).toLowerCase();
    if (['1', 'true', 'pass', 'passed'].includes(value)) return pass(label, name);
    return warn(label, `not recorded; set ${name}=passed after verification`);
  });
}

function checkCode() {
  if (!args.has('--verify-code')) {
    return [warn('Build/tests not run by status command', 'pass --verify-code for npm run build + npm test')];
  }

  const build = runCommand('npm', ['run', 'build']);
  const test = build.ok ? runCommand('npm', ['test', '--', '--runInBand']) : null;

  const checks = [
    build.ok
      ? pass('npm run build passed', `${build.durationMs}ms`)
      : fail('npm run build failed', build.output.slice(-1000))
  ];

  if (test) {
    checks.push(
      test.ok
        ? pass('npm test passed', `${test.durationMs}ms`)
        : fail('npm test failed', test.output.slice(-1000))
    );
  } else {
    checks.push(warn('npm test skipped', 'build failed'));
  }

  return checks;
}

function printSection(title, checks) {
  console.log(`\n${title}`);
  console.log('-'.repeat(title.length));
  for (const check of checks) {
    const suffix = check.details ? ` - ${check.details}` : '';
    console.log(`[${check.status}] ${check.label}${suffix}`);
  }
}

function summarize(sections) {
  const all = sections.flatMap((section) => section.checks);
  const failCount = all.filter((check) => check.status === 'FAIL').length;
  const warnCount = all.filter((check) => check.status === 'WARN').length;
  const passCount = all.filter((check) => check.status === 'PASS').length;
  return { passCount, warnCount, failCount };
}

async function main() {
  const loadedEnvFiles = loadEnvFiles();
  const configDir = resolveConfigDir();

  const sections = [
    { title: 'Code', checks: checkCode() },
    { title: 'Environment', checks: checkEnv() },
    { title: 'Credential Rotation Gate', checks: checkRotationGate() },
    { title: 'Config', checks: [...checkReposConfig(configDir), ...checkTeamAssignments(configDir)] },
    { title: 'Deployment Decisions', checks: checkDeploymentDecisions() },
    { title: 'Health', checks: await checkHealth() },
    { title: 'Smoke Tests', checks: checkSmokeFlags() }
  ];

  if (args.has('--json')) {
    console.log(JSON.stringify({
      loadedEnvFiles,
      configDir,
      sections,
      summary: summarize(sections)
    }, null, 2));
  } else {
    console.log('Boardman readiness status');
    console.log(`cwd: ${cwd}`);
    console.log(`config: ${path.relative(cwd, configDir) || '.'}`);
    console.log(`env files loaded: ${loadedEnvFiles.length ? loadedEnvFiles.join(', ') : 'none'}`);

    for (const section of sections) printSection(section.title, section.checks);

    const summary = summarize(sections);
    console.log('\nSummary');
    console.log('-------');
    console.log(`PASS: ${summary.passCount}  WARN: ${summary.warnCount}  FAIL: ${summary.failCount}`);
  }

  const summary = summarize(sections);
  if (args.has('--strict') && summary.failCount > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
