"""Single source of truth for the ClearMap version.

Consumed by report.py (report header), pyproject.toml (dynamic version), and
checked against .claude-plugin/plugin.json by tests/test_version.py.
"""
__version__ = "0.4.0"
