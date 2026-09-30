/** CVSS 技术评级与证据状态分开表达，不把风险分数拼接成“5.3 INFO”。 */
export function cvssLabel(finding: Record<string, any>): string {
  const score = Number(finding.cvss_score)
  if (finding.cvss_score == null || !Number.isFinite(score)) return '未评分'
  const level = score === 0 ? 'NONE' : score < 4 ? 'LOW' : score < 7 ? 'MEDIUM' : score < 9 ? 'HIGH' : 'CRITICAL'
  return `${score.toFixed(1)} ${level}`
}

export function evidenceLabel(finding: Record<string, any>): string {
  if (finding.verified) return '已关联验证证据'
  if (finding.supporting_evidence?.length) return '有脚本旁证，待结构化核验'
  if (finding.evidence_level === 'attempted') return '已有请求记录，尚未实证'
  return '未关联结构化请求与响应'
}

export function pocLabel(finding: Record<string, any>): string {
  if (finding.poc_source === 'tool_log') return '来源：工具请求；敏感值已脱敏'
  if (finding.poc_quality === 'missing_request') return '缺少完整复现请求或命令'
  return '来源：上报内容，需按实际身份与环境复核'
}
