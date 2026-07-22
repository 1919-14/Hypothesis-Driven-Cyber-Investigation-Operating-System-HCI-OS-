const fs = require('fs');
const path = require('path');
const markdownIt = require('markdown-it');
const katex = require('katex');
const puppeteer = require('puppeteer-core');

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const INPUT_MD = "C:\\Users\\saina\\Videos\\ET Hackathon 2.0\\docs\\pdf_data_master_final.md";
const DIAGRAM_PNG = "C:\\Users\\saina\\Videos\\ET Hackathon 2.0\\docs\\architecture_rendered.png";
const OUTPUT_PDF = "C:\\Users\\saina\\Videos\\ET Hackathon 2.0\\docs\\HCI_OS_Master_Submission.pdf";
const TEMP_HTML = "C:\\Users\\saina\\Videos\\ET Hackathon 2.0\\docs\\temp_render.html";

console.log("Reading input markdown...");
let rawMd = fs.readFileSync(INPUT_MD, 'utf8');

// 1. Remove YAML frontmatter
rawMd = rawMd.replace(/^---[\s\S]*?---\n/, '');

// 2. Remove raw LaTeX titlepage block
rawMd = rawMd.replace(/```\{=latex\}[\s\S]*?\\end\{titlepage\}\n```/, '');
rawMd = rawMd.replace(/\\newpage/g, '<div class="page-break"></div>');

// 3. Process LaTeX Math before Markdown parsing
function renderMath(text) {
  // Block Math: $$...$$ or \[...\]
  text = text.replace(/\$\$([\s\S]+?)\$\$/g, (match, math) => {
    try {
      return `<div class="math-block">${katex.renderToString(math.trim(), { displayMode: true, throwOnError: false })}</div>`;
    } catch (e) {
      return match;
    }
  });

  text = text.replace(/\\\[([\s\S]+?)\\\]/g, (match, math) => {
    try {
      return `<div class="math-block">${katex.renderToString(math.trim(), { displayMode: true, throwOnError: false })}</div>`;
    } catch (e) {
      return match;
    }
  });

  // Inline Math: $...$ or \(...\)
  // Be careful not to match currency like $50 or $0.3
  text = text.replace(/(?<!\\)\$([^\$\n]+?)\$/g, (match, math) => {
    // If it looks like monetary value (e.g. $50, $0.30), skip
    if (/^\d+(\.\d+)?$/.test(math.trim())) return match;
    try {
      return katex.renderToString(math.trim(), { displayMode: false, throwOnError: false });
    } catch (e) {
      return match;
    }
  });

  text = text.replace(/\\\(([\s\S]+?)\\\)/g, (match, math) => {
    try {
      return katex.renderToString(math.trim(), { displayMode: false, throwOnError: false });
    } catch (e) {
      return match;
    }
  });

  return text;
}

// 4. Replace DOT code block in Section 4 with rendered Image
const diagramHtml = `
<div class="diagram-card">
  <div class="diagram-header">
    <span class="diagram-badge">SYSTEM ARCHITECTURE DIAGRAM</span>
    <span class="diagram-title">Complete 13-Agent HCI-OS Multi-Tier Pipeline & Governance Control Flow</span>
  </div>
  <div class="diagram-img-wrapper">
    <img src="file:///${DIAGRAM_PNG.replace(/\\/g, '/')}" alt="HCI-OS Architecture Diagram" class="architecture-img" />
  </div>
  <div class="diagram-caption">
    <strong>Figure 4.1 — HCI-OS Full System Architecture:</strong> Illustrating External Telemetry Ingestion (T1–T4), Ingestion & Trust Gate (A1), Normalizer (A2), Fingerprint Router (A3), Tier 1 Redis Exact Match (<0.1ms), Tier 2 FAISS Vector Memory (~16ms), Tier 3 Anomaly Fusion & GNN Ensemble (A4–A6), Active Hunt Circuit Breaker (A10), Bayesian SOAR Planner (A7), Adversarial Critic (A8), Dual-Agent Sandbox (A9), Blast-Radius Decision Engine, AUTO_RESPOND / HUMAN_GATE Execution paths, SHA-256 Cryptographic Audit Chain (A12), Federation Exporter (A13), and Behavioral Watchdog Governance / Kill Switch (A11, SD-8).
  </div>
</div>
`;

// Replace dot block in section 4
rawMd = rawMd.replace(/## System Architecture Graphviz DOT Diagram[\s\S]*?```dot[\s\S]*?```/, `## System Architecture Diagram\n\n${diagramHtml}`);

// Apply Math rendering to raw Markdown
console.log("Rendering LaTeX math equations...");
const mathProcessedMd = renderMath(rawMd);

// 5. Initialize MarkdownIt parser
const md = markdownIt({
  html: true,
  linkify: true,
  typographer: true
}).enable('table');

console.log("Converting Markdown to HTML...");
let contentHtml = md.render(mathProcessedMd);

// Enhance Table styling
contentHtml = contentHtml.replace(/<table>/g, '<div class="table-container"><table>');
contentHtml = contentHtml.replace(/<\/table>/g, '</table></div>');

// Enhance Blockquote styling
contentHtml = contentHtml.replace(/<blockquote>/g, '<blockquote class="callout-box">');

// Cover Page HTML
const coverPageHtml = `
<div class="cover-page">
  <div class="cover-header">
    <div class="header-tag">FINAL SUBMISSION MASTER TECHNICAL DOCUMENTATION</div>
    <div class="event-badge">ECONOMIC TIMES × UNSTOP ET AI HACKATHON 2.0</div>
  </div>
  
  <div class="cover-title-container">
    <h1 class="cover-title">HCI-OS</h1>
    <h2 class="cover-subtitle">Hypothesis-Driven Cyber Investigation Operating System</h2>
    <p class="cover-tagline">"An AI detective, not a log viewer — it investigates hypotheses, not events."</p>
  </div>

  <div class="problem-box">
    <div class="problem-title">PROBLEM STATEMENT #7</div>
    <div class="problem-desc">AI-Powered Cyber Resilience for Critical National Infrastructure (CNI)</div>
  </div>

  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">Team Name</span><span class="meta-val highlight">PraxisCode X</span></div>
    <div class="meta-item"><span class="meta-label">Team Lead</span><span class="meta-val">V S S K Sai Narayana (Architect / Backend)</span></div>
    <div class="meta-item"><span class="meta-label">Team Member</span><span class="meta-val">Sujeet Jaiswal (Data Analysis / ML / DBMS)</span></div>
    <div class="meta-item"><span class="meta-label">Team Member</span><span class="meta-val">Sujeet Sahni (Threat Analysis / Frontend / DevOps)</span></div>
    <div class="meta-item"><span class="meta-label">Institution</span><span class="meta-val">Indore Institute of Science and Technology, Indore, MP</span></div>
    <div class="meta-item"><span class="meta-label">Programme</span><span class="meta-val">B.Tech AIML, 4th Semester</span></div>
    <div class="meta-item"><span class="meta-label">Submission Round</span><span class="meta-val">Round 2 Prototype Sprint Submission</span></div>
    <div class="meta-item"><span class="meta-label">Repository</span><span class="meta-val">github.com/1919-14/HCI-OS</span></div>
    <div class="meta-item"><span class="meta-label">Document Date</span><span class="meta-val">22 July 2026</span></div>
  </div>

  <div class="cover-footer">
    <span>CONFIDENTIAL & PROPRIETARY — PREPARED FOR ET AI HACKATHON 2.0 JURY</span>
  </div>
</div>
`;

// Read KaTeX CSS content to embed directly
const katexCssPath = require.resolve('katex/dist/katex.min.css');
const katexCss = fs.readFileSync(katexCssPath, 'utf8');

// Full HTML Template
const fullHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>HCI-OS Master Technical Documentation</title>
  <style>
    ${katexCss}

    @page {
      size: A4;
      margin: 20mm 15mm 20mm 15mm;
      @top-left {
        content: "HCI-OS Technical Documentation";
        font-family: 'Inter', system-ui, sans-serif;
        font-size: 8pt;
        font-weight: 700;
        color: #0B2545;
        border-bottom: 1px solid #CBD5E1;
        padding-bottom: 4px;
      }
      @top-right {
        content: "ET AI Hackathon 2.0 · PraxisCode X";
        font-family: 'Inter', system-ui, sans-serif;
        font-size: 8pt;
        font-weight: 600;
        color: #0F766E;
        border-bottom: 1px solid #CBD5E1;
        padding-bottom: 4px;
      }
      @bottom-left {
        content: "Confidential — Final Master Submission Data";
        font-family: 'Inter', system-ui, sans-serif;
        font-size: 8pt;
        color: #64748B;
      }
      @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'Inter', system-ui, sans-serif;
        font-size: 8pt;
        font-weight: 600;
        color: #0B2545;
      }
    }

    @page:first {
      margin: 15mm 15mm 15mm 15mm;
      @top-left { content: none; }
      @top-right { content: none; }
      @bottom-left { content: none; }
      @bottom-right { content: none; }
    }

    * {
      box-sizing: border-box;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 10pt;
      line-height: 1.55;
      color: #1E293B;
      background-color: #FFFFFF;
      margin: 0;
      padding: 0;
    }

    .page-break {
      page-break-before: always;
      break-before: page;
    }

    /* COVER PAGE STYLING */
    .cover-page {
      page-break-after: always;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      height: 250mm;
      padding: 5mm 5mm;
      font-family: 'Inter', sans-serif;
    }

    .cover-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #0F766E;
      padding-bottom: 12px;
    }

    .header-tag {
      font-size: 8.5pt;
      font-weight: 800;
      letter-spacing: 1px;
      color: #0B2545;
    }

    .event-badge {
      background: #0F766E;
      color: #FFFFFF;
      font-size: 8pt;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 4px;
      letter-spacing: 0.5px;
    }

    .cover-title-container {
      margin-top: 25px;
      margin-bottom: 25px;
    }

    .cover-title {
      font-size: 42pt;
      font-weight: 900;
      color: #0B2545;
      margin: 0;
      line-height: 1.1;
      letter-spacing: -1px;
    }

    .cover-subtitle {
      font-size: 16pt;
      font-weight: 700;
      color: #0F766E;
      margin-top: 8px;
      margin-bottom: 16px;
      line-height: 1.3;
    }

    .cover-tagline {
      font-size: 11pt;
      font-style: italic;
      color: #475569;
      background: #F8FAFC;
      border-left: 4px solid #0F766E;
      padding: 10px 14px;
      margin: 0;
      border-radius: 0 6px 6px 0;
    }

    .problem-box {
      background: linear-gradient(135deg, #0B2545 0%, #1E3A8A 100%);
      color: #FFFFFF;
      padding: 16px 20px;
      border-radius: 8px;
      margin-bottom: 25px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }

    .problem-title {
      font-size: 9pt;
      font-weight: 800;
      letter-spacing: 1px;
      color: #38BDF8;
      margin-bottom: 4px;
    }

    .problem-desc {
      font-size: 13pt;
      font-weight: 700;
      line-height: 1.3;
    }

    .meta-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px 20px;
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 20px;
    }

    .meta-item {
      display: flex;
      flex-direction: column;
    }

    .meta-label {
      font-size: 7.5pt;
      font-weight: 700;
      text-transform: uppercase;
      color: #64748B;
      letter-spacing: 0.5px;
    }

    .meta-val {
      font-size: 9.5pt;
      font-weight: 600;
      color: #0F172A;
      margin-top: 2px;
    }

    .meta-val.highlight {
      color: #0F766E;
      font-weight: 800;
    }

    .cover-footer {
      border-top: 1px solid #E2E8F0;
      padding-top: 12px;
      text-align: center;
      font-size: 8pt;
      font-weight: 600;
      color: #94A3B8;
      letter-spacing: 0.5px;
    }

    /* HEADINGS & TYPOGRAPHY */
    h1 {
      font-size: 18pt;
      font-weight: 800;
      color: #0B2545;
      border-bottom: 2px solid #0F766E;
      padding-bottom: 6px;
      margin-top: 24pt;
      margin-bottom: 12pt;
      page-break-after: avoid;
    }

    h2 {
      font-size: 13pt;
      font-weight: 700;
      color: #0F766E;
      margin-top: 18pt;
      margin-bottom: 8pt;
      page-break-after: avoid;
    }

    h3 {
      font-size: 11pt;
      font-weight: 700;
      color: #9A1B1B;
      margin-top: 14pt;
      margin-bottom: 6pt;
      page-break-after: avoid;
    }

    h4 {
      font-size: 10pt;
      font-weight: 700;
      color: #1E293B;
      margin-top: 10pt;
      margin-bottom: 4pt;
      page-break-after: avoid;
    }

    p {
      margin-top: 0;
      margin-bottom: 10pt;
      text-align: justify;
    }

    strong {
      color: #0B2545;

    }

    /* TABLES */
    .table-container {
      width: 100%;
      margin: 12pt 0;
      overflow: hidden;
      border-radius: 6px;
      border: 1px solid #CBD5E1;
      page-break-inside: avoid;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 9pt;
    }

    th {
      background-color: #0B2545;
      color: #FFFFFF;
      font-weight: 700;
      text-align: left;
      padding: 8px 12px;
      border: 1px solid #0B2545;
    }

    td {
      padding: 7px 12px;
      border: 1px solid #E2E8F0;
      vertical-align: top;
    }

    tr:nth-child(even) td {
      background-color: #F8FAFC;
    }

    /* CALLOUT BOXES & QUOTES */
    blockquote.callout-box {
      background-color: #F0FDFA;
      border-left: 4px solid #0F766E;
      color: #0F766E;
      margin: 12pt 0;
      padding: 10pt 14pt;
      border-radius: 0 6px 6px 0;
      font-size: 9.5pt;
      page-break-inside: avoid;
    }

    blockquote.callout-box p {
      margin: 0;
      text-align: left;
    }

    /* CODE BLOCKS */
    pre {
      background-color: #0F172A;
      color: #F8FAFC;
      padding: 10pt 12pt;
      border-radius: 6px;
      font-family: 'Fira Code', 'Cascadia Code', Consolas, monospace;
      font-size: 8.5pt;
      line-height: 1.45;
      overflow-x: auto;
      margin: 12pt 0;
      page-break-inside: avoid;
      white-space: pre-wrap;
      word-break: break-all;
    }

    code {
      font-family: 'Fira Code', Consolas, monospace;
      font-size: 8.5pt;
      background-color: #F1F5F9;
      color: #0F766E;
      padding: 2px 5px;
      border-radius: 4px;
      border: 1px solid #E2E8F0;
    }

    pre code {
      background-color: transparent;
      color: inherit;
      padding: 0;
      border: none;
    }

    /* MATH DISPLAY */
    .math-block {
      text-align: center;
      margin: 12pt 0;
      padding: 8pt 0;
      background-color: #F8FAFC;
      border-radius: 6px;
      border: 1px solid #E2E8F0;
      page-break-inside: avoid;
    }

    .katex-display {
      margin: 0 !important;
    }

    /* DIAGRAM CARD STYLING */
    .diagram-card {
      background: #FFFFFF;
      border: 1.5px solid #0F766E;
      border-radius: 8px;
      padding: 14px;
      margin: 16pt 0;
      box-shadow: 0 4px 12px rgba(15, 118, 110, 0.08);
      page-break-inside: avoid;
    }

    .diagram-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
      border-bottom: 1px solid #E2E8F0;
      padding-bottom: 8px;
    }

    .diagram-badge {
      background: #0B2545;
      color: #FFFFFF;
      font-size: 7.5pt;
      font-weight: 800;
      padding: 3px 8px;
      border-radius: 4px;
      letter-spacing: 0.5px;
    }

    .diagram-title {
      font-size: 10pt;
      font-weight: 700;
      color: #0F766E;
    }

    .diagram-img-wrapper {
      text-align: center;
      padding: 8px 0;
    }

    .architecture-img {
      max-width: 100%;
      height: auto;
      display: block;
      margin: 0 auto;
      border-radius: 4px;

    }

    .diagram-caption {
      font-size: 8.5pt;
      color: #475569;
      background-color: #F8FAFC;
      padding: 8px 12px;
      border-radius: 6px;
      border-left: 3px solid #0B2545;
      margin-top: 8px;
      line-height: 1.4;
    }

    /* LISTS */
    ul, ol {
      margin-top: 0;
      margin-bottom: 10pt;
      padding-left: 18pt;
    }

    li {
      margin-bottom: 4pt;
    }
  </style>
</head>
<body>
  ${coverPageHtml}
  <div class="content-body">
    ${contentHtml}
  </div>
</body>
</html>`;

console.log("Writing temporary HTML file...");
fs.writeFileSync(TEMP_HTML, fullHtml, 'utf8');

async function renderPdf() {
  console.log("Launching Edge via Puppeteer-Core...");
  const browser = await puppeteer.launch({
    executablePath: EDGE_PATH,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--allow-file-access-from-files']
  });

  const page = await browser.newPage();
  console.log("Navigating to rendered HTML...");
  await page.goto(`file:///${TEMP_HTML.replace(/\\/g, '/')}`, { waitUntil: 'networkidle0' });

  console.log("Generating PDF output...");
  await page.pdf({
    path: OUTPUT_PDF,
    format: 'A4',
    printBackground: true,
    margin: {
      top: '20mm',
      bottom: '20mm',
      left: '15mm',
      right: '15mm'
    }
  });

  await browser.close();
  console.log(`SUCCESS! Visually rich submission PDF created at:\n${OUTPUT_PDF}`);
}

renderPdf().catch(err => {
  console.error("Error generating PDF:", err);
  process.exit(1);
});
