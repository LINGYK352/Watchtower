import { t as translate } from '../i18n'
/** CVSS 技术评级与证据状态分开表达，不把风险分数拼接成“5.3 INFO”。 */
export function cvssLabel(finding: Record<string, any>): string {
  const score = Number(finding.cvss_score)
  if (finding.cvss_score == null || !Number.isFinite(score)) return translate('ui.m_f58e9a58708c')
  const level = score === 0 ? 'NONE' : score < 4 ? 'LOW' : score < 7 ? 'MEDIUM' : score < 9 ? 'HIGH' : 'CRITICAL'
  return `${score.toFixed(1)} ${level}`
}

export function evidenceLabel(finding: Record<string, any>): string {
  if (finding.verified) return translate('ui.m_9903483ce787')
  if (finding.supporting_evidence?.length) return translate('ui.m_dc9752d4b53f')
  if (finding.evidence_level === 'attempted') return translate('ui.m_db0e6dc575d1')
  return translate('ui.m_711e1ecaa8e2')
}

export function pocLabel(finding: Record<string, any>): string {
  if (finding.poc_source === 'tool_log') return translate('ui.m_2698661ec60b')
  if (finding.poc_quality === 'missing_request') return translate('ui.m_38fd931da40b')
  return translate('ui.m_d0ba8115477b')
}
