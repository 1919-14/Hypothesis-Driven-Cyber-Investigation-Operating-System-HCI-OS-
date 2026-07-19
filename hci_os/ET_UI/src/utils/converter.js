/**
 * converter.js — Universal file-to-IngestRequest converter
 *
 * Handles: JSON, CSV, XLSX, TXT, PDF (text-extraction), and raw manual input.
 * All outputs conform to { raw_event: {}, asset_id: string, source: string }.
 * Missing / malformed fields are filled with safe defaults — nothing throws.
 */

import Papa from "papaparse";
import * as XLSX from "xlsx";

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Sanitize a single object — ensure every value is a primitive (no nested objects blocked) */
const sanitize = (obj) => {
  if (!obj || typeof obj !== "object") return { message: String(obj ?? "") };
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) out[k] = "";
    else if (typeof v === "object") out[k] = JSON.stringify(v);
    else out[k] = v;
  }
  return out;
};

/** Wrap a value into a standard IngestRequest record */
const wrap = (raw_event, source = "ui-upload", asset_id = "") => ({
  raw_event: sanitize(raw_event),
  asset_id: asset_id || raw_event?.asset_id || raw_event?.host || raw_event?.src_ip || "",
  source,
});

/** Try to auto-detect asset_id from common field names */
const guessAsset = (row) =>
  row?.asset_id || row?.host || row?.hostname || row?.device || row?.src_ip || row?.ip || "";

// ── Parsers ───────────────────────────────────────────────────────────────────

const parseJSON = (text, filename) => {
  try {
    const parsed = JSON.parse(text);
    const rows = Array.isArray(parsed) ? parsed : [parsed];
    return rows
      .filter((r) => r && typeof r === "object")
      .map((r) => wrap(r, filename, guessAsset(r)));
  } catch {
    // If JSON is malformed, treat as plain text
    return [wrap({ message: text, parse_error: "invalid_json" }, filename)];
  }
};

const parseCSV = (text, filename) => {
  const { data, errors } = Papa.parse(text, {
    header: true,
    skipEmptyLines: true,
    dynamicTyping: true,
    transformHeader: (h) => h.trim().toLowerCase().replace(/\s+/g, "_"),
  });
  if (data.length === 0 && errors.length > 0) {
    return [wrap({ message: text, parse_error: errors[0]?.message }, filename)];
  }
  return data.map((row) => wrap(row, filename, guessAsset(row)));
};

const parseXLSX = (buffer, filename) => {
  try {
    const wb = XLSX.read(buffer, { type: "array" });
    const records = [];
    wb.SheetNames.forEach((sheetName) => {
      const ws = wb.Sheets[sheetName];
      const rows = XLSX.utils.sheet_to_json(ws, { defval: "" });
      rows.forEach((row) => {
        // Normalize header keys
        const normalRow = {};
        for (const [k, v] of Object.entries(row)) {
          normalRow[k.trim().toLowerCase().replace(/\s+/g, "_")] = v;
        }
        records.push(wrap(normalRow, `${filename}/${sheetName}`, guessAsset(normalRow)));
      });
    });
    return records.length > 0
      ? records
      : [wrap({ message: "empty spreadsheet", filename }, filename)];
  } catch (err) {
    return [wrap({ message: "xlsx_parse_error", error: String(err) }, filename)];
  }
};

const parseTXT = (text, filename) => {
  // Each non-empty line is treated as a separate log event
  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  if (lines.length === 0) return [wrap({ message: text }, filename)];

  return lines.map((line) => {
    // Try key=value pairs first (e.g. syslog format)
    const kvMatch = line.match(/(\w+)=("[^"]*"|\S+)/g);
    if (kvMatch && kvMatch.length >= 2) {
      const obj = {};
      kvMatch.forEach((kv) => {
        const [k, ...vParts] = kv.split("=");
        obj[k] = vParts.join("=").replace(/^"|"$/g, "");
      });
      return wrap(obj, filename, guessAsset(obj));
    }
    return wrap({ message: line }, filename);
  });
};

// PDF: read as text via FileReader (no pdfjs needed — works for most PDF exports)
const parsePDF = async (file) => {
  return new Promise((resolve) => {
    // We use the raw text inside the PDF using a binary read trick
    const reader = new FileReader();
    reader.onload = (e) => {
      const raw = e.target.result;
      // Extract printable ASCII text blocks (good enough for exported logs/reports)
      const text = raw
        .replace(/[^\x20-\x7E\n\r\t]/g, " ")
        .replace(/\s{3,}/g, "\n")
        .trim();

      const lines = text
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 10); // skip very short noise fragments

      const records = lines.map((line) =>
        wrap({ message: line, source_type: "pdf" }, file.name)
      );
      resolve(
        records.length > 0
          ? records
          : [wrap({ message: "pdf_empty_or_binary", filename: file.name }, file.name)]
      );
    };
    reader.readAsBinaryString(file);
  });
};

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Convert a File object to an array of IngestRequest-compatible objects.
 * Never throws — returns at least one record with parse_error on failure.
 */
export const fileToRecords = async (file) => {
  const ext = file.name.split(".").pop().toLowerCase();
  const filename = file.name;

  try {
    if (ext === "pdf") {
      return await parsePDF(file);
    }

    if (["xlsx", "xls", "xlsm"].includes(ext)) {
      const buffer = await file.arrayBuffer();
      return parseXLSX(new Uint8Array(buffer), filename);
    }

    // All remaining types are text-based
    const text = await file.text();

    if (ext === "json") return parseJSON(text, filename);
    if (ext === "csv") return parseCSV(text, filename);

    // TXT, LOG, MD, or unknown extension — try JSON first, then CSV, then line-by-line
    try {
      return parseJSON(text, filename);
    } catch {
      if (text.includes(",") && text.includes("\n")) {
        return parseCSV(text, filename);
      }
      return parseTXT(text, filename);
    }
  } catch (err) {
    return [wrap({ message: "converter_error", error: String(err), filename }, filename)];
  }
};

/**
 * Convert a manual text input (freeform string) to an IngestRequest.
 * Handles JSON objects, key=value strings, or raw message text.
 */
export const manualInputToRecord = (text, source = "ui-manual", assetId = "") => {
  const t = text.trim();
  // Try JSON
  try {
    const parsed = JSON.parse(t);
    return wrap(parsed, source, assetId || guessAsset(parsed));
  } catch {}
  // Try key=value
  const kvMatch = t.match(/(\w+)=("[^"]*"|\S+)/g);
  if (kvMatch && kvMatch.length >= 2) {
    const obj = {};
    kvMatch.forEach((kv) => {
      const [k, ...vParts] = kv.split("=");
      obj[k] = vParts.join("=").replace(/^"|"$/g, "");
    });
    return wrap(obj, source, assetId || guessAsset(obj));
  }
  // Plain text message
  return wrap({ message: t }, source, assetId);
};

/** Human-readable label for accepted file types */
export const ACCEPTED_EXTENSIONS = ".json,.csv,.xlsx,.xls,.txt,.log,.md,.pdf";

/** Quick check — does this file extension have a known parser? */
export const isSupportedFile = (file) =>
  /\.(json|csv|xlsx|xls|xlsm|txt|log|md|pdf)$/i.test(file.name);
