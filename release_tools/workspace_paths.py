"""Paths for local Windows build/QA tools; independent of their current cwd."""
from pathlib import Path


def development_paths(source=None):
    source = Path(source or Path(__file__).resolve().parents[1]).resolve()
    for parent in source.parents:
        engineering = parent / 'Watchtower-engineering'
        if (engineering / "workspace.py").is_file():
            return {
                "source": source,
                "validation": engineering / 'validation/windows/source-validation',
                "native": parent / 'Watchtower-windows/native-test',
                "legacy": engineering / 'docs/history/windows-vm-experiment',
                "releases": parent / 'Watchtower-windows/artifacts',
                "install_kit": parent / 'Watchtower-windows/artifacts/historical-native-candidates/install-kit',
            }
    # Exported source repositories keep the original layout unless explicitly
    # embedded in the local three-directory workspace.
    return {
        "source": source,
        "validation": source / "validation",
        "native": source.parent / 'native-test',
        "legacy": source.parent,
        "releases": source.parent / "artifacts",
        "install_kit": source / "validation/native-assessment/install-kit",
    }
