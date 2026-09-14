import type { SecurityCategory } from "./types";

const LABELS: Record<SecurityCategory, string> = {
  vulnerability: "Vulnerability",
  cloud_security: "Cloud Security",
  iam: "IAM",
  app_api: "App & API",
  supply_chain: "Supply Chain",
  data_privacy: "Data Privacy",
  ransomware: "Ransomware",
  threat_intel: "Threat Intel",
  ai_security: "AI Security",
  infrastructure: "Infrastructure",
};

export function categoryLabel(category: string): string {
  return LABELS[category as SecurityCategory] ?? category;
}
