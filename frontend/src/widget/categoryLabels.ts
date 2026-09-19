import type { AISecuritySubcategory, SecurityCategory } from "./types";

const LABELS: Record<SecurityCategory, string> = {
  insecure_design: "Insecure Design",
  cloud_security: "Cloud Security",
  iam: "IAM",
  app_api: "App & API",
  supply_chain: "Supply Chain",
  data_privacy: "Data Privacy",
  ransomware: "Ransomware & Malware",
  threat_intel: "Threat Intel",
  ai_security: "AI Security",
  infrastructure: "Infrastructure",
};

const SUBCATEGORY_LABELS: Record<AISecuritySubcategory, string> = {
  llm_vulnerability: "LLM Vulnerability",
  agent_abuse: "Agent Abuse",
  ai_data_leakage: "AI Data Leakage",
  model_poisoning: "Model Poisoning",
  ai_supply_chain: "AI Supply Chain",
  ai_infrastructure: "AI Infrastructure",
  ai_enabled_attacks: "AI-Enabled Attacks",
  misaligned_ai_permissions: "Misaligned AI Permissions",
};

export function categoryLabel(category: string): string {
  return LABELS[category as SecurityCategory] ?? category;
}

export function subcategoryLabel(subcategory: string): string {
  return SUBCATEGORY_LABELS[subcategory as AISecuritySubcategory] ?? subcategory;
}
