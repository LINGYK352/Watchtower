"""Platform metadata selects an update channel; it never grants authorization."""
import platform

def request_headers(product=None, abi=None):
    system=platform.system().strip().lower()
    if product is None:product='windows-native' if system=='windows' else 'web'
    if abi is None:abi='windows-amd64-py311-v1' if product=='windows-native' else 'web-source-v2'
    architecture=platform.machine().strip().lower()
    architecture={'x86_64':'amd64','x64':'amd64','aarch64':'arm64'}.get(architecture,architecture)
    return {'X-Client-OS':system,'X-Client-Arch':architecture,
            'X-Update-Product':product,'X-Update-ABI':abi or 'web-source-v2',
            'X-Update-Capabilities':'numeric-patch-chain-v1'}
