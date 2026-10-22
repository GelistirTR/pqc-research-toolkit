import assert from 'node:assert/strict';
import { hashPassword, passwordHashNeedsRehash, verifyPassword } from '../src/index.js';

// Synthetic in-process integration example; an application owns its DB, policy,
// rate limits, account lookup and atomic compare-and-swap when upgrading a hash.
const password = Buffer.from('Synthetic account password; never user data');
const wrong = Buffer.from('different synthetic password');
try {
  const storedRecord = await hashPassword(password);
  assert.equal(await verifyPassword(storedRecord, password), true);
  assert.equal(await verifyPassword(storedRecord, wrong), false);
  assert.equal(passwordHashNeedsRehash(storedRecord), false);
  console.log(JSON.stringify({ verified: true, wrongPasswordRejected: true,
    note: 'Store the PHC record, never this plaintext; do not log password hashes in real applications' }));
} finally { password.fill(0); wrong.fill(0); }
