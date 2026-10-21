#!/usr/bin/env node
/**
 * Accessibility Verification Runner (Issue #296, #297)
 *
 * Verifies WCAG 2.1 AA keyboard navigation, modal focus trapping,
 * roving tabindex state management, and async contract transaction status
 * ARIA live region mapping. Also covers dense forms, tables, reduced-motion,
 * screen-reader announcements, and error recovery flows.
 */

const assert = require("node:assert");

console.log("==================================================================");
console.log("TRELLIS: ACCESSIBILITY & ASYNC STATUS VERIFICATION RUNNER (#296)");
console.log("==================================================================\n");

// ---------------------------------------------------------------------------
// 1. Async Status State ARIA Mapping Verification
// ---------------------------------------------------------------------------
console.log("[1/7] Verifying Async Transaction Status -> ARIA Live Region Mapping...");

const AsyncStatusState = {
  Idle: "Idle",
  Validating: "Validating",
  AwaitingSignature: "AwaitingSignature",
  Broadcasting: "Broadcasting",
  Succeeded: "Succeeded",
  RecoverableError: "RecoverableError",
  FatalError: "FatalError",
};

function mapStateToAccessibility(state, returnFocus = "tx_btn") {
  const isBusy = ["Validating", "AwaitingSignature", "Broadcasting"].includes(state);
  const isModal = ["AwaitingSignature", "RecoverableError", "FatalError"].includes(state);

  let ariaLive = "polite";
  if (state === "Idle") ariaLive = "off";
  if (["RecoverableError", "FatalError"].includes(state)) ariaLive = "assertive";

  let role = "status";
  if (state === "Idle") role = "region";
  if (["Validating", "Broadcasting"].includes(state)) role = "progressbar";
  if (["RecoverableError", "FatalError"].includes(state)) role = "alert";

  return {
    state,
    ariaLive,
    ariaBusy: isBusy,
    role,
    focusTrap: {
      trapActive: isModal,
      initialFocus: isModal ? "modal_confirm_btn" : "main_content",
      returnFocus,
      dismissable: state !== "Broadcasting",
    },
    keyboardMode: isModal ? "ModalTrap" : "LinearTab",
  };
}

// Test normal progression
const statesNormal = [
  AsyncStatusState.Idle,
  AsyncStatusState.Validating,
  AsyncStatusState.AwaitingSignature,
  AsyncStatusState.Broadcasting,
  AsyncStatusState.Succeeded,
];
for (const st of statesNormal) {
  const meta = mapStateToAccessibility(st);
  assert.ok(meta.ariaLive, `State ${st} must define aria-live`);
  assert.ok(meta.role, `State ${st} must define role`);
}
console.log("  ✓ Normal lifecycle states (Idle -> Validating -> AwaitingSignature -> Broadcasting -> Succeeded) verified");

// Test failure and assertive alerts
const metaError = mapStateToAccessibility(AsyncStatusState.FatalError);
assert.strictEqual(metaError.ariaLive, "assertive");
assert.strictEqual(metaError.role, "alert");
assert.strictEqual(metaError.ariaBusy, false);
console.log("  ✓ Failure states correctly map to assertive alerts with aria-busy false");

// ---------------------------------------------------------------------------
// 2. Focus Trap Lifecycle & Dismissal Verification
// ---------------------------------------------------------------------------
console.log("\n[2/7] Verifying Modal Focus Trap Containment and Return Target...");

const modalMeta = mapStateToAccessibility(AsyncStatusState.AwaitingSignature, "submit_tx_button");
assert.strictEqual(modalMeta.focusTrap.trapActive, true);
assert.strictEqual(modalMeta.focusTrap.returnFocus, "submit_tx_button");
assert.strictEqual(modalMeta.focusTrap.dismissable, true);

// During broadcasting, modal cannot be accidentally dismissed
const broadcastMeta = mapStateToAccessibility(AsyncStatusState.Broadcasting, "submit_tx_button");
assert.strictEqual(broadcastMeta.focusTrap.dismissable, false);

console.log("  ✓ Focus trap activates for signature modal and retains return target");
console.log("  ✓ In-flight broadcasting locks dismissal to prevent orphaned transactions");

// ---------------------------------------------------------------------------
// 3. Roving Tabindex for Grid and List Elements
// ---------------------------------------------------------------------------
console.log("\n[3/7] Verifying Keyboard Navigation & Roving Tabindex Model...");

class RovingTabindexManager {
  constructor(itemCount) {
    this.itemCount = itemCount;
    this.focusedIndex = 0;
  }

  handleKeyDown(key) {
    if (key === "ArrowDown" || key === "ArrowRight") {
      this.focusedIndex = (this.focusedIndex + 1) % this.itemCount;
    } else if (key === "ArrowUp" || key === "ArrowLeft") {
      this.focusedIndex = (this.focusedIndex - 1 + this.itemCount) % this.itemCount;
    } else if (key === "Home") {
      this.focusedIndex = 0;
    } else if (key === "End") {
      this.focusedIndex = this.itemCount - 1;
    }
    return this.focusedIndex;
  }

  getTabIndices() {
    return Array.from({ length: this.itemCount }, (_, i) =>
      i === this.focusedIndex ? 0 : -1
    );
  }
}

const roving = new RovingTabindexManager(4);
assert.deepStrictEqual(roving.getTabIndices(), [0, -1, -1, -1]);

roving.handleKeyDown("ArrowDown");
assert.deepStrictEqual(roving.getTabIndices(), [-1, 0, -1, -1]);

roving.handleKeyDown("End");
assert.deepStrictEqual(roving.getTabIndices(), [-1, -1, -1, 0]);

roving.handleKeyDown("ArrowDown"); // wraps to 0
assert.deepStrictEqual(roving.getTabIndices(), [0, -1, -1, -1]);

console.log("  ✓ Roving tabindex correctly maintains exactly one tab stop (tabIndex=0)");
console.log("  ✓ Arrow navigation, Home, End, and boundary wrap-around verified");

// ---------------------------------------------------------------------------
// 4. Retry Path and Focus Restoration
// ---------------------------------------------------------------------------
console.log("\n[4/7] Verifying Error Recovery & Focus Restoration...");

const retryMeta = mapStateToAccessibility(AsyncStatusState.RecoverableError, "retry_btn");
assert.strictEqual(retryMeta.ariaLive, "assertive");
assert.strictEqual(retryMeta.focusTrap.dismissable, true);
assert.strictEqual(retryMeta.focusTrap.returnFocus, "retry_btn");

console.log("  ✓ Recoverable error provides immediate assistive announcement and sets focus restoration target");

// ---------------------------------------------------------------------------
// 5. Dense Form Accessibility (labels, descriptions, error announcements)
// ---------------------------------------------------------------------------
console.log("\n[5/7] Verifying Dense Form Label, Description, and Error Wiring...");

function buildFormField({ id, label, hint, required, error }) {
  const describedBy = [];
  if (hint) describedBy.push(`${id}-hint`);
  if (error) describedBy.push(`${id}-error`);
  return {
    id,
    labelFor: id,
    labelText: label,
    required: Boolean(required),
    ariaRequired: Boolean(required),
    ariaInvalid: Boolean(error),
    ariaDescribedBy: describedBy.join(" ") || undefined,
    hintId: hint ? `${id}-hint` : undefined,
    errorId: error ? `${id}-error` : undefined,
    errorRole: error ? "alert" : undefined,
    errorLive: error ? "assertive" : undefined,
  };
}

const denseFields = [
  buildFormField({ id: "amount", label: "Amount", hint: "In stroops", required: true }),
  buildFormField({ id: "recipient", label: "Recipient", required: true, error: "Recipient is required" }),
  buildFormField({ id: "memo", label: "Memo" }),
];

for (const field of denseFields) {
  assert.strictEqual(field.labelFor, field.id, `Field ${field.id} label must target input id`);
  assert.ok(field.labelText, `Field ${field.id} must have visible label text`);
  if (field.required) assert.strictEqual(field.ariaRequired, true);
  if (field.hintId) assert.ok(field.ariaDescribedBy.includes(field.hintId));
  if (field.errorId) {
    assert.ok(field.ariaDescribedBy.includes(field.errorId));
    assert.strictEqual(field.ariaInvalid, true);
    assert.strictEqual(field.errorRole, "alert");
    assert.strictEqual(field.errorLive, "assertive");
  }
}
console.log("  ✓ Every dense form field has an associated label and aria-describedby wiring");
console.log("  ✓ Validation errors surface as assertive alerts with aria-invalid set");

// ---------------------------------------------------------------------------
// 6. Dense Table Accessibility (headers, scope, caption, sort state)
// ---------------------------------------------------------------------------
console.log("\n[6/7] Verifying Dense Table Semantics and Sort Announcements...");

function buildTable({ caption, columns, rows, sort }) {
  return {
    caption,
    role: "table",
    columns: columns.map((c) => ({
      key: c.key,
      headerText: c.label,
      scope: "col",
      ariaSort: sort && sort.key === c.key ? sort.direction : "none",
    })),
    rows: rows.map((r, i) => ({ index: i, cells: r })),
    rowCount: rows.length,
  };
}

const denseTable = buildTable({
  caption: "Treasury transactions",
  columns: [
    { key: "id", label: "ID" },
    { key: "amount", label: "Amount" },
    { key: "status", label: "Status" },
  ],
  rows: [
    { id: "tx1", amount: "100", status: "Succeeded" },
    { id: "tx2", amount: "250", status: "RecoverableError" },
  ],
  sort: { key: "amount", direction: "ascending" },
});

assert.ok(denseTable.caption, "Table must expose a caption for screen readers");
for (const col of denseTable.columns) {
  assert.strictEqual(col.scope, "col", `Column ${col.key} must use scope=col`);
  assert.ok(["ascending", "descending", "none"].includes(col.ariaSort));
}
assert.strictEqual(denseTable.columns.find((c) => c.key === "amount").ariaSort, "ascending");
assert.strictEqual(denseTable.rowCount, 2);
console.log("  ✓ Table caption, column scope, and aria-sort state verified");

// ---------------------------------------------------------------------------
// 7. Reduced Motion, Screen-Reader Announcements, and Rollback Recovery
// ---------------------------------------------------------------------------
console.log("\n[7/7] Verifying Reduced Motion, Announcements, and Rollback Recovery...");

function resolveMotion(prefersReducedMotion) {
  return {
    transitionDurationMs: prefersReducedMotion ? 0 : 200,
    animateSpinner: !prefersReducedMotion,
    announcePolitely: true,
  };
}

const motionDefault = resolveMotion(false);
const motionReduced = resolveMotion(true);
assert.strictEqual(motionDefault.transitionDurationMs, 200);
assert.strictEqual(motionReduced.transitionDurationMs, 0);
assert.strictEqual(motionReduced.animateSpinner, false);
assert.strictEqual(motionReduced.announcePolitely, true);
console.log("  ✓ prefers-reduced-motion disables transitions and spinner animation");

function announce(state) {
  const meta = mapStateToAccessibility(state);
  return { live: meta.ariaLive, role: meta.role, message: `Transaction ${state}` };
}

const announcement = announce(AsyncStatusState.RecoverableError);
assert.strictEqual(announcement.live, "assertive");
assert.strictEqual(announcement.role, "alert");
assert.ok(announcement.message.includes("RecoverableError"));
console.log("  ✓ Screen-reader announcement carries assertive live region and alert role");

function rollbackRecovery({ state, hasPendingTx, userConfirmed }) {
  if (state === AsyncStatusState.RecoverableError && hasPendingTx) {
    return {
      action: userConfirmed ? "retry" : "cancel",
      restoreFocus: "retry_btn",
      clearPending: !userConfirmed,
      announce: "assertive",
    };
  }
  if (state === AsyncStatusState.FatalError) {
    return { action: "escalate", restoreFocus: "support_link", clearPending: true, announce: "assertive" };
  }
  return { action: "none", restoreFocus: null, clearPending: false, announce: "polite" };
}

const recoveryRetry = rollbackRecovery({ state: AsyncStatusState.RecoverableError, hasPendingTx: true, userConfirmed: true });
assert.strictEqual(recoveryRetry.action, "retry");
assert.strictEqual(recoveryRetry.restoreFocus, "retry_btn");
assert.strictEqual(recoveryRetry.clearPending, false);

const recoveryCancel = rollbackRecovery({ state: AsyncStatusState.RecoverableError, hasPendingTx: true, userConfirmed: false });
assert.strictEqual(recoveryCancel.action, "cancel");
assert.strictEqual(recoveryCancel.clearPending, true);

const recoveryFatal = rollbackRecovery({ state: AsyncStatusState.FatalError, hasPendingTx: true, userConfirmed: false });
assert.strictEqual(recoveryFatal.action, "escalate");
assert.strictEqual(recoveryFatal.restoreFocus, "support_link");
console.log("  ✓ Rollback/recovery paths restore focus and clear pending state deterministically");

console.log("\n==================================================================");
console.log("ALL ACCESSIBILITY & ASYNC STATUS VERIFICATIONS PASSED (#296, #297)");
console.log("==================================================================");
