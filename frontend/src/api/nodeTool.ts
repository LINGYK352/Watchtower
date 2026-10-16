import { getToken } from './request'
import { t } from '../i18n'

/** Same generic Linux program for workspaces and migration; no host is embedded. */
export async function downloadMaintenanceNode() {
  const response=await fetch('/api/collaboration/node-tool/download',{headers:{Token:getToken()}})
  if(!response.ok || !response.headers.get('content-type')?.includes('gzip'))throw new Error(t('teamCache.downloadFailed'))
  const blob=await response.blob(),magic=new Uint8Array(await blob.slice(0,2).arrayBuffer())
  if(magic[0]!==0x1f || magic[1]!==0x8b)throw new Error(t('teamCache.downloadFailed'))
  const url=URL.createObjectURL(blob),anchor=document.createElement('a')
  anchor.href=url;anchor.download='Watchtower-maintenance-node-linux-amd64.tar.gz';anchor.click()
  setTimeout(()=>URL.revokeObjectURL(url),5000)
}
