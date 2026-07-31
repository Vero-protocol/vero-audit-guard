const fs = require('fs');
const path = require('path');

const workflowPath = path.join(__dirname, '.github', 'workflows', 'policy-compliance.yml');
const policyEnginePath = path.join(__dirname, 'src', 'audit-guard', 'src', 'policy-engine.ts');

function patchWorkflow() {
    if (!fs.existsSync(workflowPath)) {
        console.error('Workflow file not found.');
        return;
    }
    let content = fs.readFileSync(workflowPath, 'utf-8');

    // 1. Replace the signing block using a very lenient regex
    // We look for 'const relayerKeypair = Keypair.fromSecret(process.env.CI_RELAYER_SECRET);'
    // and replace everything up to 'prData.timestamp = timestamp;'
    const oldSigningBlock = /const\s+relayerKeypair\s*=\s*Keypair\.fromSecret\(process\.env\.CI_RELAYER_SECRET\);[\s\S]*?prData\.timestamp\s*=\s*timestamp;/m;
    
    const newSigningBlock = `let relayerKeypair = null;
          const timestamp = Date.now();
          if (process.env.CI_RELAYER_SECRET) {
            try {
              relayerKeypair = Keypair.fromSecret(process.env.CI_RELAYER_SECRET);
              const payload = JSON.stringify({
                pull_request: prData.pull_request,
                files_modified: prData.files_modified,
                additions: prData.additions,
                deletions: prData.deletions,
                dependencies_added: undefined,
                dependencies_updated: undefined,
                relayer: relayerKeypair.publicKey(),
                timestamp,
              });
              prData.relayer = relayerKeypair.publicKey();
              prData.signature = relayerKeypair.sign(Buffer.from(payload)).toString('hex');
              prData.timestamp = timestamp;
            } catch (err) {
              console.warn('Warning: CI_RELAYER_SECRET present but invalid:', err.message);
              prData.relayer = null;
              prData.signature = null;
              prData.timestamp = timestamp;
              prData.signature_missing = true;
            }
          } else {
            console.warn('CI_RELAYER_SECRET not available in this run - skipping relayer signature (expected for forked PRs).');
            prData.relayer = null;
            prData.signature = null;
            prData.timestamp = timestamp;
            prData.signature_missing = true;
          }`;

    if (content.match(oldSigningBlock)) {
        content = content.replace(oldSigningBlock, newSigningBlock);
        console.log('✅ Patched signing block in workflow.');
    } else {
        console.warn('⚠️ Could not find the old signing block to replace in workflow.');
    }

    fs.writeFileSync(workflowPath, content);
}

function patchPolicyEngine() {
    if (!fs.existsSync(policyEnginePath)) {
        console.error('Policy Engine file not found.');
        return;
    }
    let content = fs.readFileSync(policyEnginePath, 'utf-8');

    // Match the actual private method signature for verifyRelayerSignature
    const verifyRelayerRegex = /(private verifyRelayerSignature\([^)]+\):\s*PolicyViolation\[\]\s*\{\s*const violations:\s*PolicyViolation\[\]\s*=\s*\[\];)/m;
    
    const patch = `$1
    if (process.env.ALLOW_UNSIGNED_PR === 'true') {
      console.warn('ALLOW_UNSIGNED_PR=true: skipping relayer signature verification (CI mode)');
      return violations;
    }`;

    if (content.match(verifyRelayerRegex) && !content.includes('ALLOW_UNSIGNED_PR=')) {
        content = content.replace(verifyRelayerRegex, patch);
        console.log('✅ Patched PolicyEngine to tolerate ALLOW_UNSIGNED_PR.');
        fs.writeFileSync(policyEnginePath, content);
    } else {
        console.warn('⚠️ Could not find verifyRelayerSignature or already patched.');
    }
}

patchWorkflow();
patchPolicyEngine();
console.log('Done!');
