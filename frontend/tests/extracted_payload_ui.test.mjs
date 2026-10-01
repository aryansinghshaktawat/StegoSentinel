/**
 * StegoSentinel Frontend UI Component Tests
 * Tests the Extracted Payload presentation for all decoding states,
 * binary containers, XSS escaping, and error conditions.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import sucrase from "sucrase";
import React from "react";
import ReactDOMServer from "react-dom/server";

globalThis.React = React;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const componentPath = path.resolve(__dirname, "../components/extracted-payload-view.tsx");
const sourceCode = fs.readFileSync(componentPath, "utf8");

// Transpile TypeScript + JSX
const { code: compiledCode } = sucrase.transform(sourceCode, {
  transforms: ["typescript", "jsx", "imports"],
});

// Load transpiled component module
const mod = { exports: {} };
const runner = new Function("require", "module", "exports", compiledCode);
// Mock next/link and @/lib/api for standalone rendering
const customRequire = (id) => {
  if (id === "next/link") {
    return ({ href, children, ...props }) => React.createElement("a", { href, ...props }, children);
  }
  if (id === "@/lib/api") {
    return {
      api: {
        getDownloadUrl: (id) => `/api/v1/evidence/${id}/download`,
      },
    };
  }
  return null;
};
// Bind standard node require alongside mocks
import { createRequire } from "node:module";
const nativeRequire = createRequire(import.meta.url);
runner(
  (id) => customRequire(id) || nativeRequire(id),
  mod,
  mod.exports
);

const { ExtractedPayloadView } = mod.exports;

test("1. Renders TEST_MESSAGE when decode_status is SUCCESS", () => {
  const payload = {
    candidate_id: "cand-123",
    analysis_id: "case-001",
    technique: "LSB_RGB_P0_SEQ",
    status: "VALID",
    type: "text/plain",
    payload_size: 12,
    encoding: "UTF-8",
    decode_status: "SUCCESS",
    decoded_text: "TEST_MESSAGE",
  };

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(ExtractedPayloadView, {
      payload,
      activeCandidate: {
        id: "cand-123",
        analysis_id: "case-001",
        technique: "LSB_RGB_P0_SEQ",
        parameters: { channel: "RGB", bit_plane: 0, order: "sequential" },
        final_score: 0.96,
        status: "VALID",
        decode_status: "SUCCESS",
      },
      analysisId: "case-001",
    })
  );

  assert.ok(html.includes("TEST_MESSAGE"), "UI must render TEST_MESSAGE");
  assert.ok(html.includes("EXTRACTED PAYLOAD"), "UI must include EXTRACTED PAYLOAD header");
  assert.ok(html.includes("RGB LSB"), "UI must format technique name");
  assert.ok(html.includes("Bit Plane"), "UI must show bit plane");
  assert.ok(html.includes("Plain Text"), "UI must format payload type");
  assert.ok(html.includes("UTF-8"), "UI must show encoding");
  assert.ok(html.includes("96%"), "UI must show extraction confidence");
  assert.ok(html.includes("COPY TEXT"), "UI must include COPY TEXT button");
  assert.ok(html.includes("VIEW EVIDENCE"), "UI must include VIEW EVIDENCE link");
});

test("2. Renders empty / unsuccessful extraction when no payload exists", () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(ExtractedPayloadView, {
      payload: null,
      activeCandidate: null,
      analysisId: "case-002",
    })
  );

  assert.ok(
    html.includes("Extraction unsuccessful. No candidate bitstream produced a valid payload."),
    "UI must indicate extraction was unsuccessful"
  );
  assert.ok(!html.includes("RECOVERED CONTENT"), "UI must not show recovered content section");
});

test("3. Renders binary payload metadata and download link without arbitrary binary in HTML", () => {
  const payload = {
    candidate_id: "cand-bin-456",
    analysis_id: "case-003",
    technique: "LSB_RGB_P0_SEQ",
    status: "VALID",
    type: "application/zip",
    payload_size: 188416,
    decode_status: "IDENTIFIED",
    decoded_text: null,
    evidence_object_id: "ev-obj-789",
    evidence: {
      id: "ev-obj-789",
      name: "candidate_LSB_RGB_P0_SEQ.zip",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      size: 188416,
      detected_type: "application/zip",
      download_url: "/api/v1/evidence/ev-obj-789/download",
    },
  };

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(ExtractedPayloadView, {
      payload,
      activeCandidate: {
        id: "cand-bin-456",
        analysis_id: "case-003",
        technique: "LSB_RGB_P0_SEQ",
        parameters: { channel: "RGB", bit_plane: 0, order: "sequential" },
        final_score: 0.95,
        status: "VALID",
        decode_status: "IDENTIFIED",
      },
      analysisId: "case-003",
    })
  );

  assert.ok(html.includes("PAYLOAD EXTRACTED (BINARY CONTAINER)"), "UI must show binary container heading");
  assert.ok(html.includes("Zip Archive"), "UI must show detected format");
  assert.ok(html.includes("188416 bytes"), "UI must show payload size");
  assert.ok(html.includes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "UI must show SHA-256");
  assert.ok(html.includes("DOWNLOAD EVIDENCE"), "UI must provide download button");
  assert.ok(html.includes("/api/v1/evidence/ev-obj-789/download"), "UI must link to download URL");
  assert.ok(!html.includes("PK\x03\x04"), "Raw binary must never be inlined in HTML");
});

test("4. Renders failed / partial decoding message when text could not be decoded", () => {
  const payload = {
    candidate_id: "cand-partial",
    analysis_id: "case-004",
    technique: "LSB_B_P0_SEQ",
    status: "PARTIAL",
    type: "text/partial",
    decode_status: "FAILED",
    decoded_text: null,
  };

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(ExtractedPayloadView, {
      payload,
      activeCandidate: {
        id: "cand-partial",
        analysis_id: "case-004",
        technique: "LSB_B_P0_SEQ",
        parameters: { channel: "B", bit_plane: 0, order: "sequential" },
        final_score: 0.45,
        status: "PARTIAL",
        decode_status: "FAILED",
      },
      analysisId: "case-004",
    })
  );

  assert.ok(
    html.includes("Payload extracted but could not be decoded."),
    "UI must clearly explain that payload was extracted but undecodable"
  );
});

test("5. Renders encrypted or high-entropy warning when content is encrypted", () => {
  const payload = {
    candidate_id: "cand-enc",
    analysis_id: "case-005",
    technique: "LSB_RGB_P0_SEQ",
    status: "PARTIAL",
    type: "application/octet-stream-high-entropy",
    decode_status: "ENCRYPTED_OR_UNKNOWN",
    decoded_text: null,
  };

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(ExtractedPayloadView, {
      payload,
      activeCandidate: {
        id: "cand-enc",
        analysis_id: "case-005",
        technique: "LSB_RGB_P0_SEQ",
        parameters: { channel: "RGB", bit_plane: 0, order: "sequential" },
        final_score: 0.40,
        status: "PARTIAL",
        decode_status: "ENCRYPTED_OR_UNKNOWN",
      },
      analysisId: "case-005",
    })
  );

  assert.ok(
    html.includes("Payload extracted; encrypted or unknown content."),
    "UI must show encrypted payload explanation"
  );
  assert.ok(html.includes("AES/ChaCha20"), "UI must explain high entropy without brute-forcing");
});

test("6. Renders very long payloads safely without crashing", () => {
  const longText = "FORENSIC_EVIDENCE_RECORD_ENTRY_".repeat(300); // ~9000 chars
  const payload = {
    candidate_id: "cand-long",
    analysis_id: "case-006",
    technique: "LSB_RGB_P0_SEQ",
    status: "VALID",
    type: "text/plain",
    payload_size: longText.length,
    encoding: "UTF-8",
    decode_status: "SUCCESS",
    decoded_text: longText,
  };

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(ExtractedPayloadView, {
      payload,
      activeCandidate: {
        id: "cand-long",
        analysis_id: "case-006",
        technique: "LSB_RGB_P0_SEQ",
        parameters: { channel: "RGB", bit_plane: 0, order: "sequential" },
        final_score: 0.95,
        status: "VALID",
        decode_status: "SUCCESS",
      },
      analysisId: "case-006",
    })
  );

  assert.ok(html.includes(longText), "UI must render long payload intact");
});

test("7. Malicious HTML / XSS attempts are strictly text-escaped and not executed", () => {
  const maliciousInput = '<script>alert("XSS")</script><img src=x onerror=alert(1) />';
  const payload = {
    candidate_id: "cand-xss",
    analysis_id: "case-007",
    technique: "LSB_RGB_P0_SEQ",
    status: "VALID",
    type: "text/plain",
    payload_size: maliciousInput.length,
    encoding: "UTF-8",
    decode_status: "SUCCESS",
    decoded_text: maliciousInput,
  };

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(ExtractedPayloadView, {
      payload,
      activeCandidate: {
        id: "cand-xss",
        analysis_id: "case-007",
        technique: "LSB_RGB_P0_SEQ",
        parameters: { channel: "RGB", bit_plane: 0, order: "sequential" },
        final_score: 0.95,
        status: "VALID",
        decode_status: "SUCCESS",
      },
      analysisId: "case-007",
    })
  );

  // Must NOT contain unescaped executable HTML script tag
  assert.ok(!html.includes('<script>alert("XSS")</script>'), "Unescaped script tag must not exist in HTML");
  // Must be escaped into text entities
  assert.ok(
    html.includes("&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;"),
    "Script tags must be converted to text entities"
  );
  assert.ok(
    html.includes("&lt;img src=x onerror=alert(1) /&gt;"),
    "Img onerror tags must be converted to text entities"
  );
});
