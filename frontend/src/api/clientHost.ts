export interface ClientCapabilities { desktop_updates?: boolean; desktop_version?: string }
interface HostApi {
  get_client_capabilities?: () => Promise<ClientCapabilities>
  show_program_update?: () => Promise<unknown>
}
function hostApi(): HostApi | undefined {
  return (window as unknown as { pywebview?: { api?: HostApi } }).pywebview?.api
}
export async function clientCapabilities(): Promise<ClientCapabilities> {
  if (!hostApi()?.get_client_capabilities) {
    await new Promise<void>((resolve) => {
      let timer: ReturnType<typeof setTimeout>
      const ready = () => { clearTimeout(timer); window.removeEventListener('pywebviewready', ready); resolve() }
      window.addEventListener('pywebviewready', ready, { once: true })
      timer = setTimeout(ready, 500)
    })
  }
  return hostApi()?.get_client_capabilities?.() || {}
}
export async function showProgramUpdate(): Promise<void> {
  await hostApi()?.show_program_update?.()
}
