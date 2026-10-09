import { getToken, request } from './request'
import { t as translate } from '../i18n'

export interface ConsoleAttachment { file_id: string; filename: string; bytes: number; sha256: string; path: string; created_at: number }
export const listConsoleFiles = (key: string) => request<{ items: ConsoleAttachment[]; max_bytes?: number }>(`/api/pentest/session/console/${encodeURIComponent(key)}/files`)

export function uploadConsoleFile(key: string, file: File, progress: (percent: number, loaded: number, total: number) => void, signal: AbortSignal): Promise<ConsoleAttachment> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    const abort = () => xhr.abort()
    const done = () => signal.removeEventListener('abort', abort)
    xhr.open('POST', `/api/pentest/session/console/${encodeURIComponent(key)}/files`)
    const token = getToken(); if (token) xhr.setRequestHeader('Token', token)
    xhr.upload.onprogress = e => { if (e.lengthComputable) progress(Math.min(99, Math.round(e.loaded / e.total * 100)), e.loaded, e.total) }
    xhr.onload = () => {
      done()
      try { const body = JSON.parse(xhr.responseText); if (xhr.status >= 400 || body.code !== 200) throw new Error(body.message || `HTTP ${xhr.status}`); resolve(body.data) }
      catch (e) { reject(e) }
    }
    xhr.onerror = () => { done(); reject(new Error(translate('consoleFiles.networkError'))) }
    xhr.onabort = () => { done(); reject(new DOMException('Upload cancelled', 'AbortError')) }
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) { done(); reject(new DOMException('Upload cancelled', 'AbortError')); return }
    const body = new FormData(); body.append('file', file); xhr.send(body)
  })
}
