import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import * as fs from "fs";
import * as path from "path";
import { createServer as createHttpServer } from "node:http";
import { randomUUID } from "node:crypto";

/**
 * EU AI Act Compliance Checker - MCP Server (Streamable HTTP)
 * Supports GET (SSE) + POST + DELETE as required by MCP spec
 * Public server - no authentication required
 */

// Server card metadata for Smithery scanner
const SERVER_CARD = {
  serverInfo: { name: "ArkForge Compliance Scanner", version: "1.2.0" },
  capabilities: { tools: { listChanged: true } },
  tools: [
    { name: "scan_project", description: "Scan a project to detect AI model usage (EU AI Act)", inputSchema: { type: "object", properties: { project_path: { type: "string", description: "Absolute path to the project to scan" } }, required: ["project_path"] } },
    { name: "check_compliance", description: "Check EU AI Act compliance for a given risk category", inputSchema: { type: "object", properties: { project_path: { type: "string", description: "Absolute path to the project" }, risk_category: { type: "string", enum: ["unacceptable", "high", "limited", "minimal"], default: "limited" } }, required: ["project_path"] } },
    { name: "generate_report", description: "Generate EU AI Act compliance report", inputSchema: { type: "object", properties: { project_path: { type: "string" }, risk_category: { type: "string", enum: ["unacceptable", "high", "limited", "minimal"], default: "limited" } }, required: ["project_path"] } },
    { name: "gdpr_scan_project", description: "Scan a project for personal data processing patterns (GDPR)", inputSchema: { type: "object", properties: { project_path: { type: "string", description: "Absolute path to the project to scan" } }, required: ["project_path"] } },
    { name: "gdpr_check_compliance", description: "Check GDPR compliance based on data processing role", inputSchema: { type: "object", properties: { project_path: { type: "string" }, processing_role: { type: "string", enum: ["controller", "processor", "minimal_processing"], default: "controller" } }, required: ["project_path"] } },
    { name: "gdpr_generate_report", description: "Generate GDPR compliance report", inputSchema: { type: "object", properties: { project_path: { type: "string" }, processing_role: { type: "string", enum: ["controller", "processor", "minimal_processing"], default: "controller" } }, required: ["project_path"] } },
    { name: "gdpr_generate_templates", description: "Generate GDPR compliance document templates", inputSchema: { type: "object", properties: { processing_role: { type: "string", enum: ["controller", "processor", "minimal_processing"], default: "controller" } }, required: [] } },
  ],
};

// --- AI Model Patterns ---
const AI_MODEL_PATTERNS: Record<string, RegExp[]> = {
  openai: [
    /openai\.ChatCompletion/i, /openai\.Completion/i,
    /from openai import/i, /import openai/i,
    /gpt-3\.5/i, /gpt-4/i, /text-davinci/i,
  ],
  anthropic: [
    /from anthropic import/i, /import anthropic/i,
    /claude-/i, /Anthropic\(\)/i, /messages\.create/i,
  ],
  huggingface: [
    /from transformers import/i, /AutoModel/i, /AutoTokenizer/i,
    /pipeline\(/i, /huggingface_hub/i,
  ],
  tensorflow: [/import tensorflow/i, /from tensorflow import/i, /tf\.keras/i],
  pytorch: [/import torch/i, /from torch import/i, /nn\.Module/i],
  langchain: [/from langchain import/i, /import langchain/i, /LLMChain/i, /ChatOpenAI/i],
};

const RISK_CATEGORIES: Record<string, { description: string; requirements: string[] }> = {
  unacceptable: {
    description: "Prohibited systems (behavioral manipulation, social scoring, mass biometric surveillance)",
    requirements: ["Prohibited system - Do not deploy"],
  },
  high: {
    description: "High-risk systems (recruitment, credit scoring, law enforcement)",
    requirements: [
      "Complete technical documentation", "Risk management system",
      "Data quality and governance", "Transparency and user information",
      "Human oversight", "Robustness, accuracy and cybersecurity",
      "Quality management system", "Registration in EU database",
    ],
  },
  limited: {
    description: "Limited-risk systems (chatbots, deepfakes)",
    requirements: ["Transparency obligations", "Clear user information about AI interaction", "AI-generated content marking"],
  },
  minimal: {
    description: "Minimal-risk systems (spam filters, video games)",
    requirements: ["No specific obligations", "Voluntary code of conduct encouraged"],
  },
};

const BLOCKED_PATHS = [
  "/opt/claude-ceo", "/etc", "/root", "/proc",
  "/sys", "/dev", "/run", "/boot", "/usr", "/bin", "/sbin",
  "/lib", "/snap", "/mnt", "/media",
];

const MAX_FILES = 5000;
const MAX_FILE_SIZE = 1_000_000;
const CODE_EXTENSIONS = new Set([".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c"]);

function validatePath(projectPath: string): { safe: boolean; error: string } {
  let resolved: string;
  try { resolved = fs.realpathSync(projectPath); }
  catch { return { safe: false, error: `Invalid path: ${projectPath}` }; }
  for (const blocked of BLOCKED_PATHS) {
    if (resolved === blocked || resolved.startsWith(blocked + "/")) {
      return { safe: false, error: `Access denied: scanning ${blocked} is not allowed for security reasons` };
    }
  }
  return { safe: true, error: "" };
}

function walkDir(dir: string, maxFiles: number): string[] {
  const results: string[] = [];
  const queue = [dir];
  while (queue.length > 0 && results.length < maxFiles) {
    const current = queue.shift()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(current, { withFileTypes: true }); }
    catch { continue; }
    for (const entry of entries) {
      if (results.length >= maxFiles) break;
      const fullPath = path.join(current, entry.name);
      if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "__pycache__") continue;
      if (entry.isDirectory()) { queue.push(fullPath); }
      else if (entry.isFile() && CODE_EXTENSIONS.has(path.extname(entry.name))) {
        try { const stat = fs.statSync(fullPath); if (stat.size <= MAX_FILE_SIZE) results.push(fullPath); }
        catch { /* skip */ }
      }
    }
  }
  return results;
}

const FREE_TIER_BANNER = "Free tier: 10 scans/day — Pro: unlimited scans + CI/CD API at 29€/mo → https://mcp.arkforge.fr/fr/pricing.html";

function addBanner(result: Record<string, any>): Record<string, any> {
  result.upgrade = FREE_TIER_BANNER;
  return result;
}

function scanProject(projectPath: string) {
  const { safe, error } = validatePath(projectPath);
  if (!safe) return { error, detected_models: {} };
  if (!fs.existsSync(projectPath)) return { error: `Project path does not exist: ${projectPath}`, detected_models: {} };
  const files = walkDir(projectPath, MAX_FILES);
  const detectedModels: Record<string, string[]> = {};
  const aiFiles: { file: string; frameworks: string[] }[] = [];
  for (const filePath of files) {
    let content: string;
    try { content = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    const fileDetections: string[] = [];
    for (const [framework, patterns] of Object.entries(AI_MODEL_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(content)) {
          fileDetections.push(framework);
          if (!detectedModels[framework]) detectedModels[framework] = [];
          detectedModels[framework].push(path.relative(projectPath, filePath));
          break;
        }
      }
    }
    if (fileDetections.length > 0) {
      aiFiles.push({ file: path.relative(projectPath, filePath), frameworks: [...new Set(fileDetections)] });
    }
  }
  return { files_scanned: files.length, ai_files: aiFiles, detected_models: detectedModels };
}

function fileExists(projectPath: string, filename: string): boolean {
  return fs.existsSync(path.join(projectPath, filename)) || fs.existsSync(path.join(projectPath, "docs", filename));
}

function checkFileQuality(projectPath: string, filename: string): { exists: boolean; customized: boolean; unfilled_placeholders: number } {
  for (const dir of [projectPath, path.join(projectPath, "docs")]) {
    const filePath = path.join(dir, filename);
    if (fs.existsSync(filePath)) {
      try {
        const content = fs.readFileSync(filePath, "utf-8");
        const matches = content.match(/\[(?:Your |e\.g\.|Date|Duration|Role|Describe|Email)/g);
        const unfilled = matches ? matches.length : 0;
        return { exists: true, customized: unfilled <= 2, unfilled_placeholders: unfilled };
      } catch {
        return { exists: true, customized: false, unfilled_placeholders: -1 };
      }
    }
  }
  return { exists: false, customized: false, unfilled_placeholders: 0 };
}

function checkCompliance(projectPath: string, riskCategory: string) {
  if (!RISK_CATEGORIES[riskCategory]) {
    return { error: `Invalid risk category: ${riskCategory}. Valid: ${Object.keys(RISK_CATEGORIES).join(", ")}` };
  }
  const info = RISK_CATEGORIES[riskCategory];
  const readmeExists = fs.existsSync(path.join(projectPath, "README.md"));
  let status: Record<string, boolean> = {};
  if (riskCategory === "high") {
    status = {
      technical_documentation: ["README.md", "ARCHITECTURE.md", "API.md", "docs"].some(d => fs.existsSync(path.join(projectPath, d))),
      risk_management: fileExists(projectPath, "RISK_MANAGEMENT.md"),
      transparency: fileExists(projectPath, "TRANSPARENCY.md") || readmeExists,
      data_governance: fileExists(projectPath, "DATA_GOVERNANCE.md"),
      human_oversight: fileExists(projectPath, "HUMAN_OVERSIGHT.md"),
      robustness: fileExists(projectPath, "ROBUSTNESS.md"),
    };
  } else if (riskCategory === "limited") {
    const readmeLower = readmeExists ? fs.readFileSync(path.join(projectPath, "README.md"), "utf-8").toLowerCase() : "";
    const aiKeywords = ["ai", "artificial intelligence", "machine learning", "deep learning", "gpt", "claude", "llm"];
    status = {
      transparency: readmeExists || fileExists(projectPath, "TRANSPARENCY.md"),
      user_disclosure: aiKeywords.some(kw => readmeLower.includes(kw)),
      content_marking: false,
    };
    try {
      const pyFiles = walkDir(projectPath, 500).filter(f => f.endsWith(".py"));
      const markers = ["generated by ai", "généré par ia", "ai-generated", "machine-generated"];
      for (const f of pyFiles) {
        try {
          const c = fs.readFileSync(f, "utf-8").toLowerCase();
          if (markers.some(m => c.includes(m))) { status.content_marking = true; break; }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  } else if (riskCategory === "minimal") {
    status = { basic_documentation: readmeExists };
  }
  const total = Object.keys(status).length;
  const passed = Object.values(status).filter(Boolean).length;
  return {
    risk_category: riskCategory, description: info.description, requirements: info.requirements,
    compliance_status: status, compliance_score: `${passed}/${total}`,
    compliance_percentage: total > 0 ? Math.round((passed / total) * 1000) / 10 : 0,
  };
}

function generateReport(projectPath: string, riskCategory: string) {
  const scan = scanProject(projectPath);
  if ("error" in scan && scan.error) return { error: scan.error };
  const compliance = checkCompliance(projectPath, riskCategory);
  if ("error" in compliance && compliance.error) return { error: compliance.error };
  const recommendations: string[] = [];
  const compStatus = (compliance as any).compliance_status || {};
  for (const [check, passed] of Object.entries(compStatus)) {
    if (!passed) recommendations.push(`MISSING: Create documentation for: ${check.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}`);
  }
  if (recommendations.length === 0) recommendations.push("All basic checks passed");
  if (riskCategory === "high") recommendations.push("WARNING: High-risk system - EU database registration required before deployment");
  else if (riskCategory === "limited") recommendations.push("INFO: Limited-risk system - Ensure full transparency compliance");
  return {
    report_date: new Date().toISOString(), project_path: projectPath,
    scan_summary: { files_scanned: (scan as any).files_scanned || 0, ai_files_detected: ((scan as any).ai_files || []).length, frameworks_detected: Object.keys((scan as any).detected_models || {}) },
    compliance_summary: { risk_category: riskCategory, compliance_score: (compliance as any).compliance_score || "0/0", compliance_percentage: (compliance as any).compliance_percentage || 0 },
    detailed_findings: { detected_models: (scan as any).detected_models || {}, compliance_checks: compStatus, requirements: (compliance as any).requirements || [] },
    recommendations,
  };
}

// ============================================================
// GDPR — Personal Data Processing Detection
// ============================================================

const GDPR_CODE_PATTERNS: Record<string, RegExp[]> = {
  pii_fields: [
    /\bemail\b.*=/i, /\bphone\b.*=/i, /\baddress\b.*=/i,
    /\bfirst_name\b/i, /\blast_name\b/i, /\bfull_name\b/i,
    /\bdate_of_birth\b/i, /\bssn\b/i, /\bnational_id\b/i,
    /\bip_address\b/i, /\buser_agent\b/i,
  ],
  database_queries: [
    /SELECT\s+.*FROM\s+users/i, /INSERT\s+INTO\s+users/i,
    /UPDATE\s+users\s+SET/i, /DELETE\s+FROM\s+users/i,
    /User\.objects\./i, /User\.query\./i,
  ],
  cookie_operations: [
    /document\.cookie/i, /res\.cookie\(/i, /set_cookie\(/i,
    /setCookie\(/i, /response\.set_cookie/i,
  ],
  user_tracking: [
    /analytics\.track/i, /analytics\.identify/i, /gtag\(/i,
    /fbq\(/i, /mixpanel\.track/i, /posthog\.capture/i,
  ],
  consent_mechanism: [
    /consent/i, /opt.in/i, /opt.out/i, /cookie.banner/i,
    /cookie.consent/i, /gdpr.consent/i,
  ],
  data_deletion: [
    /delete.account/i, /delete.user/i, /right.to.erasure/i,
    /anonymize/i, /pseudonymize/i,
  ],
  encryption_usage: [
    /bcrypt\.hash/i, /argon2\.hash/i, /hashlib\./i,
    /crypto\.createHash/i, /encrypt\(/i, /decrypt\(/i,
  ],
  data_export: [
    /export.data/i, /download.data/i, /data.portability/i,
    /to_csv/i, /to_json.*user/i,
  ],
  ip_logging: [
    /request\.ip\b/i, /request\.remote_addr/i, /X-Forwarded-For/i,
    /REMOTE_ADDR/i,
  ],
  geolocation: [
    /navigator\.geolocation/i, /geoip/i, /maxmind/i, /ip2location/i,
  ],
};

// GDPR config/manifest patterns: libraries that process personal data
const GDPR_CONFIG_PATTERNS: Record<string, RegExp[]> = {
  database_orm: [
    /"sqlalchemy"/i, /"django"/i, /"sequelize"/i, /"prisma"/i,
    /"mongoose"/i, /"typeorm"/i, /"peewee"/i, /"tortoise-orm"/i,
  ],
  analytics: [
    /"google-analytics"/i, /"@google-analytics\//i, /"segment"/i,
    /"mixpanel"/i, /"amplitude"/i, /"posthog"/i, /"plausible"/i, /"matomo"/i,
  ],
  email_service: [
    /"sendgrid"/i, /"mailgun"/i, /"nodemailer"/i,
    /"mailchimp"/i, /"ses"/i, /"postmark"/i,
  ],
  auth_provider: [
    /"passport"/i, /"auth0"/i, /"firebase-admin"/i,
    /"keycloak"/i, /"next-auth"/i, /"supertokens"/i,
  ],
  payment: [/"stripe"/i, /"braintree"/i, /"paypal"/i],
  cookie_tracking: [/"cookie-parser"/i, /"js-cookie"/i, /"react-cookie"/i, /"cookies-next"/i],
  cloud_storage: [/"boto3"/i, /"aws-sdk"/i, /"@aws-sdk\//i, /"google-cloud-storage"/i, /"azure-storage"/i],
  encryption: [/"bcrypt"/i, /"argon2"/i, /"cryptography"/i, /"passlib"/i],
};

const CONFIG_FILE_NAMES = new Set([
  "package.json", "package-lock.json", "requirements.txt", "requirements-dev.txt",
  "setup.py", "setup.cfg", "pyproject.toml", "Pipfile", "Pipfile.lock",
  "Cargo.toml", "go.mod", "Gemfile", "composer.json",
]);

function walkConfigFiles(dir: string, maxFiles: number): string[] {
  const results: string[] = [];
  const queue = [dir];
  while (queue.length > 0 && results.length < maxFiles) {
    const current = queue.shift()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(current, { withFileTypes: true }); }
    catch { continue; }
    for (const entry of entries) {
      if (results.length >= maxFiles) break;
      const fullPath = path.join(current, entry.name);
      if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "__pycache__") continue;
      if (entry.isDirectory()) { queue.push(fullPath); }
      else if (entry.isFile() && CONFIG_FILE_NAMES.has(entry.name)) {
        try { const stat = fs.statSync(fullPath); if (stat.size <= MAX_FILE_SIZE) results.push(fullPath); }
        catch { /* skip */ }
      }
    }
  }
  return results;
}

const GDPR_REQUIREMENTS: Record<string, { description: string; requirements: string[] }> = {
  controller: {
    description: "Data controller (you decide why and how personal data is processed)",
    requirements: [
      "Lawful basis for processing (Art. 6)", "Privacy notice (Art. 13-14)",
      "DPIA if high risk (Art. 35)", "Records of processing (Art. 30)",
      "DPO if required (Art. 37)", "Data breach notification (Art. 33-34)",
      "Data subject rights (Art. 15-22)", "DPA with processors (Art. 28)",
    ],
  },
  processor: {
    description: "Data processor (you process data on behalf of a controller)",
    requirements: [
      "DPA with controller (Art. 28)", "Records of processing (Art. 30)",
      "Security measures (Art. 32)", "Breach notification to controller (Art. 33)",
    ],
  },
  minimal_processing: {
    description: "Minimal personal data processing",
    requirements: ["Privacy notice (Art. 13)", "Lawful basis documented (Art. 6)", "Basic security (Art. 32)"],
  },
};

function gdprScanProject(projectPath: string) {
  const { safe, error } = validatePath(projectPath);
  if (!safe) return { error, detected_patterns: {} };
  if (!fs.existsSync(projectPath)) return { error: `Path does not exist: ${projectPath}`, detected_patterns: {} };

  const files = walkDir(projectPath, MAX_FILES);
  const detectedPatterns: Record<string, string[]> = {};
  const flaggedFiles: { file: string; categories: string[] }[] = [];

  for (const filePath of files) {
    let content: string;
    try { content = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    const detections: string[] = [];
    for (const [category, patterns] of Object.entries(GDPR_CODE_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(content)) {
          detections.push(category);
          if (!detectedPatterns[category]) detectedPatterns[category] = [];
          detectedPatterns[category].push(path.relative(projectPath, filePath));
          break;
        }
      }
    }
    if (detections.length > 0) {
      flaggedFiles.push({ file: path.relative(projectPath, filePath), categories: [...new Set(detections)] });
    }
  }

  // Also scan config/manifest files for data-processing libraries
  const configFiles = walkConfigFiles(projectPath, MAX_FILES);
  for (const filePath of configFiles) {
    let content: string;
    try { content = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    const detections: string[] = [];
    for (const [category, patterns] of Object.entries(GDPR_CONFIG_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(content)) {
          detections.push(category);
          if (!detectedPatterns[category]) detectedPatterns[category] = [];
          detectedPatterns[category].push(path.relative(projectPath, filePath));
          break;
        }
      }
    }
    if (detections.length > 0) {
      flaggedFiles.push({ file: path.relative(projectPath, filePath), categories: [...new Set(detections)] });
    }
  }

  const hasPii = !!detectedPatterns.pii_fields || !!detectedPatterns.database_queries;
  const hasTracking = !!detectedPatterns.user_tracking;
  const hasConsent = !!detectedPatterns.consent_mechanism;
  const hasDeletion = !!detectedPatterns.data_deletion || !!detectedPatterns.data_export;
  const hasEncryption = !!detectedPatterns.encryption_usage;
  const hasGeo = !!detectedPatterns.geolocation;
  const riskFactors = [hasPii, hasTracking, hasGeo, !hasConsent && hasPii].filter(Boolean).length;

  return {
    files_scanned: files.length,
    flagged_files: flaggedFiles,
    detected_patterns: detectedPatterns,
    processing_summary: {
      processes_personal_data: hasPii || hasTracking,
      risk_level: riskFactors >= 3 ? "high" : riskFactors >= 1 ? "medium" : "low",
      positive_signals: [
        ...(hasConsent ? ["Consent mechanism detected"] : []),
        ...(hasDeletion ? ["Data deletion/export detected"] : []),
        ...(hasEncryption ? ["Encryption usage detected"] : []),
      ],
      processing_role: hasPii ? "controller" : hasTracking ? "processor" : "minimal_processing",
    },
  };
}

function gdprCheckCompliance(projectPath: string, processingRole: string) {
  if (!GDPR_REQUIREMENTS[processingRole]) {
    return { error: `Invalid role: ${processingRole}. Valid: ${Object.keys(GDPR_REQUIREMENTS).join(", ")}` };
  }
  const info = GDPR_REQUIREMENTS[processingRole];
  const scan = gdprScanProject(projectPath);
  const dp = (scan as any).detected_patterns || {};

  const status: Record<string, boolean> = {
    privacy_policy: fileExists(projectPath, "PRIVACY_POLICY.md") || fileExists(projectPath, "privacy-policy.md"),
    consent_mechanism: !!dp.consent_mechanism,
    data_subject_rights: !!dp.data_deletion || !!dp.data_export,
    security_measures: !!dp.encryption_usage,
    records_of_processing: fileExists(projectPath, "RECORDS_OF_PROCESSING.md"),
  };

  if (processingRole === "controller") {
    status.dpia = fileExists(projectPath, "DPIA.md") || fileExists(projectPath, "DATA_PROTECTION_IMPACT_ASSESSMENT.md");
    status.data_breach_procedure = fileExists(projectPath, "DATA_BREACH_PROCEDURE.md");
    status.dpa = fileExists(projectPath, "DATA_PROCESSING_AGREEMENT.md") || fileExists(projectPath, "DPA.md");
  }

  const fileChecks: Record<string, string> = {
    privacy_policy: "PRIVACY_POLICY.md",
    records_of_processing: "RECORDS_OF_PROCESSING.md",
  };
  if (processingRole === "controller") {
    fileChecks.dpia = "DPIA.md";
    fileChecks.data_breach_procedure = "DATA_BREACH_PROCEDURE.md";
  }

  const quality_notes: Record<string, string> = {};
  for (const [checkName, fname] of Object.entries(fileChecks)) {
    if (status[checkName]) {
      const quality = checkFileQuality(projectPath, fname);
      if (!quality.customized) {
        quality_notes[checkName] = `File exists but appears to be an unfilled template (${quality.unfilled_placeholders} placeholder sections remaining)`;
      }
    }
  }

  const total = Object.keys(status).length;
  const passed = Object.values(status).filter(Boolean).length;
  return {
    regulation: "GDPR", processing_role: processingRole, description: info.description,
    requirements: info.requirements, compliance_status: status,
    compliance_score: `${passed}/${total}`,
    compliance_percentage: total > 0 ? Math.round((passed / total) * 1000) / 10 : 0,
    quality_notes,
    scan_summary: (scan as any).processing_summary || {},
  };
}

function gdprGenerateReport(projectPath: string, processingRole: string) {
  const scan = gdprScanProject(projectPath);
  if ("error" in scan && scan.error) return { error: scan.error };
  const compliance = gdprCheckCompliance(projectPath, processingRole);
  if ("error" in compliance && compliance.error) return { error: compliance.error };

  const recommendations: string[] = [];
  const compStatus = (compliance as any).compliance_status || {};
  for (const [check, passed] of Object.entries(compStatus)) {
    if (!passed) recommendations.push(`MISSING: ${check.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())} — required by GDPR`);
  }
  if (recommendations.length === 0) recommendations.push("All basic GDPR checks passed");

  return {
    report_date: new Date().toISOString(), regulation: "GDPR", project_path: projectPath,
    scan_summary: { files_scanned: (scan as any).files_scanned || 0, flagged_files: ((scan as any).flagged_files || []).length, categories: Object.keys((scan as any).detected_patterns || {}) },
    processing_summary: (scan as any).processing_summary || {},
    compliance_summary: { processing_role: processingRole, compliance_score: (compliance as any).compliance_score || "0/0", compliance_percentage: (compliance as any).compliance_percentage || 0 },
    recommendations,
  };
}

// ============================================================
// GDPR — Compliance Templates
// ============================================================

const GDPR_TEMPLATES: Record<string, { filename: string; content: string }> = {
  privacy_policy: {
    filename: "PRIVACY_POLICY.md",
    content: `# Privacy Policy — GDPR Art. 13-14

## 1. Controller Identity
- **Organization**: [Your company name]
- **Contact**: [Email address]
- **DPO**: [DPO contact if applicable]

## 2. Data We Collect
| Data Category | Examples | Legal Basis | Retention |
|---------------|----------|-------------|-----------|
| Account data | Email, name | Contract (Art. 6.1.b) | Until account deletion |
| Usage data | Pages visited, features used | Legitimate interest (Art. 6.1.f) | [Duration] |
| Payment data | Transaction ID (no card numbers) | Contract (Art. 6.1.b) | Legal obligation period |

## 3. How We Use Your Data
- [Purpose 1: e.g., Provide the service]
- [Purpose 2: e.g., Send transactional emails]

## 4. Third-Party Processors
| Processor | Purpose | Location | DPA |
|-----------|---------|----------|-----|
| [e.g. Stripe] | Payment processing | US (SCCs) | Yes |
| [e.g. OVH] | Hosting | EU | Yes |

## 5. Your Rights (Art. 15-22)
You have the right to:
- **Access** your personal data (Art. 15)
- **Rectify** inaccurate data (Art. 16)
- **Erase** your data ("right to be forgotten") (Art. 17)
- **Restrict** processing (Art. 18)
- **Data portability** (Art. 20)
- **Object** to processing (Art. 21)

To exercise these rights: [contact method]
Response time: within 1 month.

## 6. Data Security
[Describe security measures: encryption, access control, etc.]

## 7. International Transfers
[Describe if data is transferred outside EU/EEA and safeguards used]

## 8. Complaints
You can lodge a complaint with your local supervisory authority (e.g., CNIL in France).

## 9. Updates
This policy was last updated on [Date]. We will notify you of significant changes.
`,
  },
  dpia: {
    filename: "DPIA.md",
    content: `# Data Protection Impact Assessment — GDPR Art. 35

## 1. Processing Description
- **Processing activity**: [Describe what personal data is processed and how]
- **Purpose**: [Why this processing is necessary]
- **Data categories**: [Types of personal data involved]
- **Data subjects**: [Who is affected: users, employees, customers]
- **Volume**: [Approximate number of data subjects]

## 2. Necessity & Proportionality
- **Legal basis**: [Art. 6 basis: consent, contract, legitimate interest, etc.]
- **Necessity**: [Why this processing is necessary for the stated purpose]
- **Proportionality**: [Why less intrusive alternatives are insufficient]
- **Data minimization**: [How you limit data collection to what's needed]

## 3. Risk Assessment
| Risk | Likelihood | Impact | Affected Rights | Mitigation |
|------|-----------|--------|-----------------|------------|
| [Unauthorized access] | [Low/Med/High] | [Low/Med/High] | [Privacy, security] | [Encryption, access control] |
| [Data breach] | [Low/Med/High] | [Low/Med/High] | [Privacy] | [Monitoring, incident response] |

## 4. Measures to Mitigate Risks
- [Measure 1: e.g., End-to-end encryption]
- [Measure 2: e.g., Access logging and monitoring]
- [Measure 3: e.g., Regular security audits]

## 5. DPO Opinion
[If applicable, include DPO review and recommendation]

## 6. Review Schedule
- **Next review**: [Date or trigger event]
- **Review frequency**: [Annual or after significant changes]
`,
  },
  records_of_processing: {
    filename: "RECORDS_OF_PROCESSING.md",
    content: `# Records of Processing Activities — GDPR Art. 30

## Controller Information
- **Name**: [Organization]
- **Contact**: [Contact details]
- **DPO**: [If applicable]

## Processing Activities

### Activity 1: [e.g., User Account Management]
| Field | Value |
|-------|-------|
| Purpose | [e.g., Provide user accounts for the service] |
| Legal basis | [e.g., Contract Art. 6.1.b] |
| Data categories | [e.g., Name, email, password hash] |
| Data subjects | [e.g., Registered users] |
| Recipients | [e.g., Hosting provider (OVH)] |
| International transfers | [e.g., None / US with SCCs] |
| Retention period | [e.g., Until account deletion + 30 days] |
| Security measures | [e.g., Encryption at rest, bcrypt passwords] |
`,
  },
  data_breach_procedure: {
    filename: "DATA_BREACH_PROCEDURE.md",
    content: `# Data Breach Response Procedure — GDPR Art. 33-34

## 1. Breach Detection
- **Monitoring**: [How breaches are detected: alerts, logs, user reports]
- **Classification**: Assess severity using: data type, volume, encryption status, affected individuals

## 2. Response Timeline (Art. 33)
| Action | Deadline | Responsible |
|--------|----------|-------------|
| Initial assessment | Within 4 hours | [Role] |
| DPA notification (if required) | Within 72 hours | [DPO/Role] |
| Data subject notification (if high risk) | Without undue delay | [Role] |
| Post-incident review | Within 2 weeks | [Role] |

## 3. DPA Notification Content (Art. 33.3)
- Nature of the breach (categories and approximate number of data subjects)
- Name and contact of DPO or contact point
- Likely consequences of the breach
- Measures taken or proposed to address the breach

## 4. Data Subject Notification (Art. 34)
Required when breach is likely to result in HIGH RISK to rights and freedoms.
Must include: clear language, nature of breach, DPO contact, likely consequences, measures taken.

## 5. Documentation
Document ALL breaches (even those not requiring notification):
- Date of detection
- Nature of breach
- Data and individuals affected
- Consequences
- Remedial actions taken

## 6. Post-Incident Review
- Root cause analysis
- Process improvements
- Staff training updates if needed
`,
  },
};

const GDPR_TEMPLATE_MAPPING: Record<string, string[]> = {
  controller: ["privacy_policy", "dpia", "records_of_processing", "data_breach_procedure"],
  processor: ["records_of_processing", "data_breach_procedure"],
  minimal_processing: ["privacy_policy"],
};

function gdprGenerateTemplates(processingRole: string) {
  if (!GDPR_REQUIREMENTS[processingRole]) {
    return { error: `Invalid role: ${processingRole}. Valid: ${Object.keys(GDPR_REQUIREMENTS).join(", ")}` };
  }
  const applicable = GDPR_TEMPLATE_MAPPING[processingRole] || ["privacy_policy"];
  const templates: Record<string, any> = {};
  for (const key of applicable) {
    if (GDPR_TEMPLATES[key]) {
      const tmpl = GDPR_TEMPLATES[key];
      templates[key] = {
        filename: `docs/${tmpl.filename}`,
        content: tmpl.content,
        instructions: `Save as docs/${tmpl.filename}, fill in [bracketed] sections`,
      };
    }
  }
  return {
    regulation: "GDPR",
    processing_role: processingRole,
    templates_count: Object.keys(templates).length,
    templates,
    usage: "Save each template in your project's docs/ directory. Fill in [bracketed] sections. Re-run gdpr_check_compliance to verify.",
  };
}

// --- API Key Management (Paywall Step 2) ---

const API_KEYS_ROOT = path.join(__dirname, "..", "api_keys.json");
const API_KEYS_DATA = path.join(__dirname, "..", "data", "api_keys.json");

class ApiKeyManager {
  private keys: Map<string, { email: string; plan: string; active: boolean }> = new Map();
  private loadedAt = 0;

  constructor() {
    this.reload();
  }

  private reload() {
    const merged = new Map<string, { email: string; plan: string; active: boolean }>();
    // Load both api_keys.json files, supporting both formats:
    // List format: {"keys": [{"key": "...", ...}]}
    // Dict format: {"mcp_pro_...": {"email": "...", ...}}
    for (const filePath of [API_KEYS_ROOT, API_KEYS_DATA]) {
      try {
        const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
        for (const entry of (data.keys || [])) {
          if (entry.key) merged.set(entry.key, { email: entry.email || "", plan: entry.plan || entry.tier || "pro", active: entry.active !== false });
        }
        for (const [apiKey, info] of Object.entries(data)) {
          if (apiKey === "keys") continue;
          if (typeof info === "object" && info !== null) {
            const i = info as any;
            merged.set(apiKey, { email: i.email || "", plan: i.plan || i.tier || "pro", active: i.active !== false });
          }
        }
      } catch { /* missing or corrupt */ }
    }
    this.keys = merged;
    this.loadedAt = Date.now();
  }

  verify(key: string): { email: string; plan: string } | null {
    // Reload from disk every 60s
    if (Date.now() - this.loadedAt > 60_000) this.reload();
    const entry = this.keys.get(key);
    if (entry && entry.active) return { email: entry.email, plan: entry.plan };
    return null;
  }
}

const apiKeyManager = new ApiKeyManager();

// --- Rate Limiting (Paywall Step 1) ---
const FREE_TIER_DAILY_LIMIT = 10;
const RATE_LIMITS_PATH = path.join(__dirname, "..", "data", "rate_limits.json");

class RateLimiter {
  private clients: Map<string, { count: number; reset_at: number }> = new Map();
  private lastCleanup: number = Date.now();

  constructor() {
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(RATE_LIMITS_PATH)) {
        const data = JSON.parse(fs.readFileSync(RATE_LIMITS_PATH, "utf-8"));
        const now = Date.now() / 1000;
        for (const [ip, entry] of Object.entries(data)) {
          const e = entry as { count: number; reset_at: number };
          if (e.reset_at > now) {
            this.clients.set(ip, { count: e.count, reset_at: e.reset_at });
          }
        }
      }
    } catch { /* start fresh on corruption */ }
  }

  private persist() {
    try {
      const obj: Record<string, { count: number; reset_at: number }> = {};
      for (const [ip, entry] of this.clients) obj[ip] = entry;
      fs.mkdirSync(path.dirname(RATE_LIMITS_PATH), { recursive: true });
      fs.writeFileSync(RATE_LIMITS_PATH, JSON.stringify(obj));
    } catch { /* non-blocking */ }
  }

  check(ip: string): { allowed: boolean; remaining: number } {
    const now = Date.now() / 1000;
    if (Date.now() - this.lastCleanup > 3_600_000) {
      this.cleanup();
      this.lastCleanup = Date.now();
    }
    const entry = this.clients.get(ip);
    if (!entry || now >= entry.reset_at) {
      this.clients.set(ip, { count: 1, reset_at: now + 86400 });
      this.persist();
      return { allowed: true, remaining: FREE_TIER_DAILY_LIMIT - 1 };
    }
    if (entry.count >= FREE_TIER_DAILY_LIMIT) {
      return { allowed: false, remaining: 0 };
    }
    entry.count++;
    this.persist();
    return { allowed: true, remaining: FREE_TIER_DAILY_LIMIT - entry.count };
  }

  private cleanup() {
    const now = Date.now() / 1000;
    for (const [ip, entry] of this.clients) {
      if (now >= entry.reset_at) this.clients.delete(ip);
    }
    this.persist();
  }
}

const rateLimiter = new RateLimiter();

function getClientIp(req: { headers: Record<string, string | string[] | undefined>; socket?: { remoteAddress?: string } }): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    return (typeof forwarded === "string" ? forwarded : forwarded[0]).split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function extractApiKey(req: { headers: Record<string, string | string[] | undefined> }): string | undefined {
  const xApiKey = req.headers["x-api-key"];
  if (xApiKey) return typeof xApiKey === "string" ? xApiKey : xApiKey[0];
  const auth = req.headers["authorization"];
  const authStr = typeof auth === "string" ? auth : auth?.[0];
  if (authStr?.startsWith("Bearer ")) return authStr.slice(7);
  return undefined;
}

// --- MCP Server with Streamable HTTP + OAuth ---

function createMcpServer() {
  const srv = new McpServer({ name: "ArkForge Compliance Scanner", version: "1.2.0" });

  srv.tool("scan_project", "Scan a project to detect AI model usage (OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain, Gemini, Mistral, Cohere, Bedrock, Azure OpenAI, Ollama, LlamaIndex, Replicate, Groq). Free: 10 scans/day. Pro: unlimited + CI/CD API → https://mcp.arkforge.fr/fr/pricing.html",
    { project_path: z.string().describe("Absolute path to the project to scan") },
    async ({ project_path }) => ({ content: [{ type: "text" as const, text: JSON.stringify(addBanner(scanProject(project_path)), null, 2) }] })
  );

  srv.tool("check_compliance", "Check EU AI Act compliance for a given risk category. Free: 10 scans/day. Pro: unlimited → https://mcp.arkforge.fr/fr/pricing.html", {
    project_path: z.string().describe("Absolute path to the project"),
    risk_category: z.enum(["unacceptable", "high", "limited", "minimal"]).default("limited").describe("EU AI Act risk category"),
  }, async ({ project_path, risk_category }) => ({
    content: [{ type: "text" as const, text: JSON.stringify(addBanner(checkCompliance(project_path, risk_category)), null, 2) }],
  }));

  srv.tool("generate_report", "Generate a complete EU AI Act compliance report with scan results, compliance checks, and recommendations. Free: 10 scans/day. Pro: unlimited → https://mcp.arkforge.fr/fr/pricing.html", {
    project_path: z.string().describe("Absolute path to the project"),
    risk_category: z.enum(["unacceptable", "high", "limited", "minimal"]).default("limited").describe("EU AI Act risk category"),
  }, async ({ project_path, risk_category }) => ({
    content: [{ type: "text" as const, text: JSON.stringify(addBanner(generateReport(project_path, risk_category)), null, 2) }],
  }));

  // --- GDPR Tools ---

  srv.tool("gdpr_scan_project", "Scan a project to detect personal data processing patterns (GDPR). Detects: PII fields, database queries, cookies, tracking, analytics, geolocation, consent mechanisms, encryption, data deletion. Free: 10 scans/day. Pro: unlimited → https://mcp.arkforge.fr/fr/pricing.html",
    { project_path: z.string().describe("Absolute path to the project to scan") },
    async ({ project_path }) => ({ content: [{ type: "text" as const, text: JSON.stringify(addBanner(gdprScanProject(project_path)), null, 2) }] })
  );

  srv.tool("gdpr_check_compliance", "Check GDPR compliance for a project based on its data processing role. Free: 10 scans/day. Pro: unlimited → https://mcp.arkforge.fr/fr/pricing.html", {
    project_path: z.string().describe("Absolute path to the project"),
    processing_role: z.enum(["controller", "processor", "minimal_processing"]).default("controller").describe("GDPR processing role"),
  }, async ({ project_path, processing_role }) => ({
    content: [{ type: "text" as const, text: JSON.stringify(addBanner(gdprCheckCompliance(project_path, processing_role)), null, 2) }],
  }));

  srv.tool("gdpr_generate_report", "Generate a complete GDPR compliance report with data processing scan, compliance checks, and recommendations. Free: 10 scans/day. Pro: unlimited → https://mcp.arkforge.fr/fr/pricing.html", {
    project_path: z.string().describe("Absolute path to the project"),
    processing_role: z.enum(["controller", "processor", "minimal_processing"]).default("controller").describe("GDPR processing role"),
  }, async ({ project_path, processing_role }) => ({
    content: [{ type: "text" as const, text: JSON.stringify(addBanner(gdprGenerateReport(project_path, processing_role)), null, 2) }],
  }));

  srv.tool("gdpr_generate_templates", "Generate GDPR compliance document templates (privacy policy, DPIA, records of processing, data breach procedure). Templates include GDPR article references and fill-in sections. Free: 10 scans/day. Pro: unlimited → https://mcp.arkforge.fr/fr/pricing.html", {
    processing_role: z.enum(["controller", "processor", "minimal_processing"]).default("controller").describe("GDPR processing role"),
  }, async ({ processing_role }) => ({
    content: [{ type: "text" as const, text: JSON.stringify(addBanner(gdprGenerateTemplates(processing_role)), null, 2) }],
  }));

  return srv;
}

// Sandbox server for Smithery scanning (returns unconnected server)
export function createSandboxServer() { return createMcpServer(); }
export default createMcpServer;

// --- HTTP Server with OAuth + Streamable HTTP Transport ---

const PORT = 8090;

// Store transports per session for proper lifecycle management
const transports = new Map<string, StreamableHTTPServerTransport>();

const httpServer = createHttpServer(async (req, res) => {
  // CORS headers on all responses
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id, Authorization");
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Server card metadata for Smithery scanner discovery
  if (req.url === "/.well-known/mcp/server-card.json" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(SERVER_CARD));
    return;
  }

  // Health check endpoint for monitoring (Gardien daemon)
  if (req.url === "/health" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      service: "mcp-eu-ai-act",
      version: SERVER_CARD.serverInfo.version,
      sessions: transports.size,
      timestamp: new Date().toISOString(),
    }));
    return;
  }

  // --- /api/verify-key endpoint (POST) ---
  if (req.url === "/api/verify-key" && req.method === "POST") {
    const bodyStr = await new Promise<string>((resolve) => {
      let data = "";
      req.on("data", (chunk: Buffer) => { data += chunk.toString(); });
      req.on("end", () => resolve(data));
    });
    try {
      const parsed = JSON.parse(bodyStr);
      const apiKey = parsed.key || "";
      const result = apiKeyManager.verify(apiKey);
      if (result) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ valid: true, plan: result.plan, email: result.email }));
      } else {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ valid: false, error: "Invalid or inactive API key" }));
      }
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ valid: false, error: 'Invalid JSON body. Expected: {"key": "your_api_key"}' }));
    }
    return;
  }

  // Only handle /mcp path for MCP requests
  if (req.url !== "/mcp") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found. MCP endpoint is at /mcp" }));
    return;
  }

  // Parse body for POST requests
  let body: string | undefined;
  if (req.method === "POST") {
    body = await new Promise<string>((resolve) => {
      let data = "";
      req.on("data", (chunk: Buffer) => { data += chunk.toString(); });
      req.on("end", () => resolve(data));
    });
  }

  // Force Accept header to include both required types for StreamableHTTPServerTransport
  // Smithery gateway/scanner may send missing, partial, or */* Accept headers → 406 error
  // Fix: patch both req.headers AND req.rawHeaders (Hono reads rawHeaders, not headers)
  const acceptVal = "application/json, text/event-stream";
  const currentAccept = req.headers["accept"] || "";
  if (!currentAccept.includes("text/event-stream") || !currentAccept.includes("application/json")) {
    (req.headers as any)["accept"] = acceptVal;
    // Patch rawHeaders (array of [name, value, name, value, ...])
    let found = false;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i].toLowerCase() === "accept") {
        req.rawHeaders[i + 1] = acceptVal;
        found = true;
        break;
      }
    }
    if (!found) {
      req.rawHeaders.push("Accept", acceptVal);
    }
  }

  // Check for existing session
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  // Route to existing session
  if (sessionId && transports.has(sessionId)) {
    const transport = transports.get(sessionId)!;
    let parsedBody: any = undefined;
    if (body) {
      try { parsedBody = JSON.parse(body); } catch { /* let transport handle invalid JSON */ }
    }

    // Rate limit tools/call requests for free tier
    if (parsedBody) {
      const requests = Array.isArray(parsedBody) ? parsedBody : [parsedBody];
      const toolsCallReq = requests.find((r: any) => r.method === "tools/call");
      if (toolsCallReq) {
        const apiKey = extractApiKey(req as any);
        let isPro = false;
        if (apiKey) {
          const keyInfo = apiKeyManager.verify(apiKey);
          if (keyInfo && keyInfo.plan === "pro") isPro = true;
        }
        if (!isPro) {
          const ip = getClientIp(req as any);
          const { allowed } = rateLimiter.check(ip);
          if (!allowed) {
            res.writeHead(429, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              jsonrpc: "2.0",
              error: {
                code: -32000,
                message: `Rate limit exceeded (${FREE_TIER_DAILY_LIMIT}/day free tier). Upgrade to Pro for unlimited scans: https://mcp.arkforge.fr/fr/pricing.html`,
              },
              id: toolsCallReq.id || null,
            }));
            return;
          }
        }
      }
    }

    try {
      await transport.handleRequest(req, res, parsedBody);
    } catch (e) {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    }
    return;
  }

  // New session (POST initialize)
  if (req.method === "POST" && body) {
    try {
      const parsed = JSON.parse(body);
      if (parsed.method === "initialize") {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID().replace(/-/g, ""),
        });

        // Create a fresh MCP server per session
        const sessionServer = createMcpServer();

        // When transport closes, clean up
        transport.onclose = () => {
          const sid = res.getHeader("mcp-session-id") as string;
          if (sid) transports.delete(sid);
          sessionServer.close().catch(() => {});
        };

        await sessionServer.connect(transport);
        await transport.handleRequest(req, res, parsed);

        // Store transport by session ID
        const sid = res.getHeader("mcp-session-id") as string;
        if (sid) transports.set(sid, transport);
        return;
      }
    } catch (e) {
      if (!res.headersSent) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
      }
      return;
    }
  }

  // No valid session for non-initialize requests
  res.writeHead(400, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Bad Request: No valid session. Send initialize first." }));
});

httpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP EU AI Act server listening on http://0.0.0.0:${PORT}/mcp`);
  console.log("Server card: /.well-known/mcp/server-card.json");
  console.log("Supports: POST (JSON-RPC), GET (SSE), DELETE (session close), OPTIONS (CORS)");
  console.log("Public server - no authentication required");
});
