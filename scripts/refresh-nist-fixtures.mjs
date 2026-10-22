// Explicit maintenance task, never runs during install, tests or CI.
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';

const commit = '975de31eb83d87039ec88934fdc47d8c312b892d';
const base = `https://raw.githubusercontent.com/usnistgov/ACVP-Server/${commit}/gen-val/json-files/`;
const sources = [];
async function load(folder) {
  const url = `${base}${folder}/internalProjection.json`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Fixture download failed: HTTP ${response.status}`);
  const text = await response.text();
  sources.push({ url, sha256: createHash('sha256').update(text).digest('hex') });
  return JSON.parse(text);
}

const kem = await load('ML-KEM-encapDecap-FIPS203');
const dsa = await load('ML-DSA-sigVer-FIPS204');
const kemGroup = kem.testGroups.find((g) => g.parameterSet === 'ML-KEM-1024' && g.function === 'decapsulation');
const dsaGroup = dsa.testGroups.find((g) => g.parameterSet === 'ML-DSA-87' &&
  g.signatureInterface === 'external' && g.preHash === 'pure');
if (!kemGroup || !dsaGroup || kem.algorithm !== 'ML-KEM' || dsa.algorithm !== 'ML-DSA') {
  throw new Error('Unexpected upstream fixture schema');
}
const output = {
  description: 'PUBLIC TEST KEYS ONLY. Selected complete ACVP groups, not the complete validation suite.',
  repository: 'https://github.com/usnistgov/ACVP-Server', commit, sources,
  kemGroupId: kemGroup.tgId,
  kemDecapsulation: kemGroup.tests.map(({ tcId, dk, c, k, reason }) => ({ tcId, dk, c, k, reason })),
  dsaGroupId: dsaGroup.tgId,
  dsaVerification: dsaGroup.tests.map(({ tcId, pk, message, context, signature, testPassed, reason }) =>
    ({ tcId, pk, message, context, signature, testPassed, reason })),
};
mkdirSync('test/fixtures', { recursive: true });
writeFileSync('test/fixtures/nist-acvp.json', `${JSON.stringify(output, null, 2)}\n`);
console.log(`Saved ${output.kemDecapsulation.length} KEM and ${output.dsaVerification.length} signature cases.`);
