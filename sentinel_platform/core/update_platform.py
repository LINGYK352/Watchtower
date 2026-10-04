"""Platform metadata selects an update channel; it never grants authorization."""
import platform

def request_headers(product='web', abi=None):
    system=platform.system().strip().lower()
    architecture=platform.machine().strip().lower()
    architecture={'x86_64':'amd64','x64':'amd64','aarch64':'arm64'}.get(architecture,architecture)
    return {'X-Client-OS':system,'X-Client-Arch':architecture,
            'X-Update-Product':product,'X-Update-ABI':abi or 'web-source-v2'}
