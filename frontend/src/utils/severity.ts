import { t as translate } from '../i18n'

export function severityLabel(value: unknown): string {
  const key = String(value || '').trim().toLowerCase()
  const rating = key === 'none' ? 'info' : key
  return translate(`severity.${['critical', 'high', 'medium', 'low', 'info'].includes(rating) ? rating : 'unrated'}`)
}
