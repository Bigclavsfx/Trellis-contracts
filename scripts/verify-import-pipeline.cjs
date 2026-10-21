/**
 * Verification script for the Trellis Contracts secure import pipeline.
 *
 * This script exercises the import pipeline in a deterministic, offline way:
 *   1. Preview  - parse + validate rows without mutating state.
 *   2. Quarantine - unsafe rows are isolated with reasons.
 *   3. Commit    - accepted rows are traceable via a deterministic digest.
 *   4. Rollback   - committed batches can be reversed from a snapshot.
 *
 *"… Run: `node scripts/verify-import-pipeline.c》`
 * Exits non-zero on any failure. No network access is required.
 */
'use strict';

const crypto = require('crypto');

const SUPPORTED_KINDS = new Set(['treasury', 'aid', 'referral', 'governance', 'oracle', 'marketplace']);
const MAX_ROWS = 10000;
const MAX_AMOUNT = 1000000000000000000n;

class ImportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ImportError';
  }
}

// -----------------------------------------------------------------------------
// Deterministic digest helpers (accepted rows traceability)
// -----------------------------------------------------------------------------
function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

function digest(value) {
  return crypto.createHash('sha256').update(stableStringify(value)).digest('hex');
}

// -----------------------------------------------------------------------------
// Row validation: pure function, no side effects.
// Returns null when valid, otherwise a reason string.
// -----------------------------------------------------------------------------
function validateRow(row, index) {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) {
    return `row[${index}] is not an object`;
  }
  if (typeof row.id !== 'string' || row.id.trim() === '') {
    return `row[${index}].id is required`;
  }
  if (!SUPPORTED_KINDS.has(row.kind)) {
    return `row[${index}].kind '${row.kind}' is not supported`;
  }
  if (typeof row.amount !== 'string' || !/^[0-9]+$/.test(row.amount)) {
    return `row[${index}].amount must be a positive integer string`;
  }
  const amount = BigInt(row.amount);
  if (amount <= 0n) {
    return `row[${index}].amount must be greater than zero`;
  }
  if (amount > MAX_AMOUNT) {
    return `row[${index}].amount exceeds maximum of ${MAX_AMOUNT}`;
  }
  if (typeof row.account !== 'string' || !/^G[A-Z0-9]{56}$/.test(row.account)) {
    return `row[${index}].account is not a valid Stellar account`;
  }
  if (row.memo !== undefined && (typeof row.memo !== 'string' || row.memo.length > 28)) {
    return `row[${index}].memo must be a string of at most 28 chars`;
  }
  if (row.referralCode !== undefined && !/^[A-Z0-9]{4,16}$/.test(row.referralCode)) {
    return `row[${index}].referralCode is malformed`;
  }
  if (row.kind === 'oracle' && (typeof row.price !== 'string' || !/^[0-9]+$/.test(row.price))) {
    return `row[${index}].price is required for oracle rows`;
  }
  return null;
}

// -----------------------------------------------------------------------------
// Preview: validate without mutating state. Produces a quarantine list
// and a traceable accepted set.
// -----------------------------------------------------------------------------
function previewImport(rows) {
  if (!Array.isArray(rows)) {
    throw new ImportError('import payload must be an array of rows');
  }
  if (rows.length > MAX_ROWS) {
    throw new ImportError(`import payload exceeds maximum of ${MAX_ROWS} rows`);
  }
  const accepted = [];
  const quarantined = [];
  const seenIds = new Set();
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const reason = validateRow(row, i);
    if (reason) {
      quarantined.push({ index: i, reason, row });
      continue;
    }
    if (seenIds.has(row.id)) {
      quarantined.push({ index: i, reason: `duplicate row id '${row.id}'`, row });
      continue;
    }
    seenIds.add(row.id);
    accepted.push({ index: i, row });
  }
  return {
    accepted,
    quarantined,
    digest: digest(accepted.map((r) => r.row)),
  };
}

// -----------------------------------------------------------------------------
// Commit: applies accepted rows to a mutable store. Stores a snapshot
// for rollback and records traceability metadata.
// -----------------------------------------------------------------------------
function commitIndividual(store, preview, batchId) {
  if (!store || typeof store.get !== 'function' || typeof store.set !== 'function') {
    throw new ImportError('store must expose get/set');
  }
  if (!batchId) {
    throw new ImportError('batchId is required for traceability');
  }
  const snapshot = new Map();
  const applied = [];
  try {
    for (const { index, row } of preview.accepted) {
      snapshot.set(row.id, store.get(row.id));
      store.set(row.id, { ...row, importBatch: batchId, importIndex: index });
      applied.push(row.id);
    }
  } catch (err) {
    // Atomic rollback on partial failure.
    for (const id of applied) {
      const previous = snapshot.get(id);
      if (previous === undefined) {
        store.delete(id);
      } else {
        store.set(id, previous);
      }
    }
    throw new ImportError(`commit failed and was rolled back: ${err.message}`);
  }
  return {
    batchId,
    digest: preview.digest,
    applied,
    snapshot,
  };
}

function rollbackBatch(store, commitReceipt) {
  if (!commitReceipt || !commitReceipt.snapshot) {
    throw new ImportError('commit receipt with snapshot is required');
  }
  const reverted = [];
  for (const id of commitReceipt.applied) {
    const previous = commitReceipt.snapshot.get(id);
    if (previous === undefined) {
      store.delete(id);
    } else {
      store.set(id, previous);
    }
    reverted.push(id);
  }
  return { batchId: commitReceipt.batchId, reverted };
}

// -----------------------------------------------------------------------------
// Test harness (zero dependencies)
// -----------------------------------------------------------------------------
function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
}

function makeStore() {
  const map = new Map();
  return {
    get: id => map.get(id),
    set: (id, value) => map.set(id, value),
    delete: id => map.delete(id),
    size: () => map.size,
    has: id => map.has(id),
  };
}

const validAccount = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const goodRows = [
  { id: 'tr-101', kind: 'treasury', amount: '10000', account: validAccount },
  { id: 'aid-201', kind: 'aid', amount: '5000', account: validAccount, memo: 'aid-round-1' },
  { id: 'ref-301', kind: 'referral', amount: '250', account: validAccount, referralCode: 'ABCD' },
];

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test('preview accepts valid rows and produces stable digest', () => {
  const a = previewImport(goodRows);
  const b = previewImport(goodRows);
  assert(a.accepted.length === 3, 'all rows accepted');
  assert(a.quarantined.length === 0, 'no quarantined rows');
  assert(a.digest === b.digest, 'digest is deterministic');
  assert(a.digest.length === 64, 'digest is sha256 hex');
});

test('preview quarantines unsafe rows with reasons', () => {
  const rows = [
    goodRows[0],
    { id: 'bad-1', kind: 'unknown', amount: '1', account: validAccount },
    { id: 'bad-2', kind: 'treasury', amount: '-5', account: validAccount },
    { id: 'bad-3', kind: 'treasury', amount: '10', account: 'not-an-account' },
    { id: 'bad-4', kind: 'oracle', amount: '10', account: validAccount },
  ];
  const p = previewImport(rows);
  assert(p.accepted.length === 1, 'only good row accepted');
  assert(p.quarantined.length === 4, 'four quarantined rows');
  for (const entry of p.quarantined) {
    assert(typeof entry.reason === 'string' && entry.reason.length > 0, 'quarantine reason present');
  }
});

test('preview rejects duplicate row ids', () => {
  const rows = [goodRows[0], { ...goodRows[0], amount: '999' }];
  const p = previewImport(rows);
  assert(p.accepted.length === 1, 'one accepted');
  assert(p.quarantined.length === 1, 'one quarantined');
  assert(/duplicate/.test(p.quarantined[0].reason), 'reason mentions duplicate');
});

test('preview rejects non-array payloads', () => {
  let threw = false;
  try { previewImport('not an array'); } catch (e) { threw = e.name === 'ImportError'; }
  assert(threw, 'throws ImportError');
});

test('commit applies accepted rows with traceability metadata', () => {
  const store = makeStore();
  const p = previewImport(goodRows);
  const receipt = commitIndividual(store, p, 'batch-123');
  assert(receipt.applied.length === 3, '3 rows applied');
  for (const id of receipt.applied) {
    const record = store.get(id);
    assert(record.importBatch === 'batch-123', 'importBatch recorded');
    assert(typeof record.importIndex === 'number', 'importIndex recorded');
  }
  assert(receipt.digest === p.digest, 'receipt digest matches preview');
});

test('commit rolls back atomically on partial failure', () => {
  const store = makeStore();
  const p = previewImport(goodRows);
  let calls = 0;
  const failingStore = {
    get: id => store.get(id),
    set: (id, v) => { calls++; if (calls === 2) throw new Error('disk full'); store.set(id, v); },
    delete: id => store.delete(id),
  };
  let threw = false;
  try { commitIndividual(failingStore, p, 'batch-fail'); } catch (e) { threw = /rolled back/.test(e.message); }
  assert(threw, 'throws rollback error');
  assert(store.size() === 0, 'store is empty after rollback');
});

test('rollback restores previous values and removes new ones', () => {
  const store = makeStore();
  store.set('tr-101', { id: 'tr-101', kind: 'treasury', amount: '1', account: validAccount });
  const p = previewImport(goodRows);
  const receipt = commitIndividual(store, p, 'batch-rb');
  const result = rollbackBatch(store, receipt);
  assert(result.reverted.length === 3, '3 rows reverted');
  assert(store.get('tr-101').amount === '1', 'pre-existing value restored');
  assert(!store.has('aid-201'), 'newly inserted row removed');
  assert(!store.has('ref-301'), 'newly inserted row removed');
});

test('rollback requires a commit receipt', () => {
  const store = makeStore();
  let threw = false;
  try { rollbackBatch(store, null); } catch (e) { threw = e.name === 'ImportError'; }
  assert(threw, 'throws ImportError');
});

test('retry after quarantine produces a clean commit', () => {
  const store = makeStore();
  const rows = [goodRows[0], { id: 'bad-1', kind: 'unknown', amount: '1', account: validAccount }];
  const preview1 = previewImport(rows);
  assert(preview1.quarantined.length === 1, 'first pass quarantines bad row');
  const retryRows = preview1.accepted.map((e) => e.row);
  const preview2 = previewImport(retryRows);
  assert(preview2.quarantined.length === 0, 'retry is clean');
  const receipt = commitIndividual(store, preview2, 'batch-retry');
  assert(receipt.applied.length === 1, 'retry commits accepted rows');
});

function main() {
  let passed = 0;
  const failures = [];
  for (const { name, fn } of tests) {
    try {
      fn();
      passed++;
      console.log(`pass  ${name}`);
    } catch (err) {
      failures.push({ name, err });
      console.error(`fail  ${name}\n      ${err.message}`);
    }
  }
  console.log(`\n${passed}/${tests.length} import pipeline checks passed`);
  if (failures.length > 0) {
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  previewImport,
  commitIndividual,
  rollbackBatch,
  validateRow,
  digest,
};
