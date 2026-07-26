const assert = require('assert');

// Mock browser globals for content.js
global.chrome = {
  runtime: {
    onMessage: { addListener: () => {} }
  },
  storage: {
    sync: { get: () => {} }
  }
};
global.document = {
  createElement: () => ({}),
  querySelectorAll: () => []
};

const content = require('./content/content.js');

const {
  checkLookalikeDomain,
  checkBrandInSubdomainTrick,
  analyzeSender,
  extractMailedByDomain,
  BRAND_DOMAINS
} = content;

console.log("Running PED Unit Tests...\n");

// 1. checkLookalikeDomain tests
console.log("Testing checkLookalikeDomain...");
// Exact matches should bypass
assert.strictEqual(checkLookalikeDomain("amazon.com"), null, "Exact match should be null");
assert.strictEqual(checkLookalikeDomain("google.com"), null, "Exact match should be null");
// Lookalikes
const micosoft = checkLookalikeDomain("micosoft.com");
assert.ok(micosoft, "Should detect micosoft.com as lookalike");
assert.strictEqual(micosoft.brand, "microsoft");

const paypa1 = checkLookalikeDomain("paypa1.com");
assert.ok(paypa1, "Should detect paypa1.com as lookalike");
assert.strictEqual(paypa1.brand, "paypal");

// Unrelated domains shouldn't flag
assert.strictEqual(checkLookalikeDomain("example.com"), null, "Unrelated domain should be null");

// 2. checkBrandInSubdomainTrick tests
console.log("Testing checkBrandInSubdomainTrick...");
assert.strictEqual(checkBrandInSubdomainTrick("paypal.com.verify-secure.net", "verify-secure.net"), "paypal", "Detects paypal in subdomain");
assert.strictEqual(checkBrandInSubdomainTrick("support.amazon.com.update.net", "update.net"), "amazon", "Detects amazon in subdomain");
// Genuine subdomains should not trigger it
assert.strictEqual(checkBrandInSubdomainTrick("support.paypal.com", "paypal.com"), null, "Genuine paypal subdomain should be null");

// 3. analyzeSender tests (pure logic decoupled from DOM)
console.log("Testing analyzeSender...");
// Normal clean sender
const clean = analyzeSender("Bob Smith", "bob@example.com", null, null);
assert.strictEqual(clean.score, 0, "Clean sender should have score 0");

// Reply-to mismatch
const replySpoof = analyzeSender("Bob", "bob@example.com", "hacker@evil.com", null);
assert.ok(replySpoof.score > 0, "Reply-to spoof should add score");
assert.ok(replySpoof.flags.some(f => f.toLowerCase().includes("reply-to")), "Should flag reply-to mismatch");

// Mailed-by mismatch
const mailedSpoof = analyzeSender("Amazon Support", "support@amazon.com", null, "sendgrid.net");
assert.ok(mailedSpoof.score > 0, "Mailed-by mismatch should add score");
assert.ok(mailedSpoof.flags.some(f => f.toLowerCase().includes("mailed-by")), "Should flag mailed-by mismatch");

// Display name spoofing
const dnSpoof = analyzeSender("PayPal Support", "random@evil.com", null, null);
assert.ok(dnSpoof.score > 0, "Display name spoofing should add score");
assert.ok(dnSpoof.flags.some(f => f.toLowerCase().includes("paypal")), "Should flag display name claiming brand");

// 4. extractMailedByDomain DOM fallback tests
console.log("Testing extractMailedByDomain DOM fallback...");
const originalQuery = global.document.querySelectorAll;

// Scenario: No expanded sender header (.gE), but there is an unrelated span[data-hovercard-id] in the document.
// This mimics a chat sidebar contact being mistaken for the "mailed-by" domain.
global.document.querySelectorAll = (sel) => {
  if (sel === "span[data-hovercard-id]") {
    return [{ innerText: "chess.com", offsetParent: {} }];
  }
  return [];
};

const result = extractMailedByDomain();
assert.strictEqual(result, null, "Should return null when header is not expanded, ignoring unrelated hovercards");

global.document.querySelectorAll = originalQuery;

console.log("\nAll tests passed successfully! ✅");
