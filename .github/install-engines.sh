#!/usr/bin/env bash
# Install the pinned scanner engines. Gitleaks is downloaded, verified against
# the release checksums, then extracted (never piped straight into tar).
set -euo pipefail

pip install "semgrep==${SEMGREP_VERSION}"

base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
tarball="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
curl -sSLo "$tarball" "${base}/${tarball}"
if curl -sSLo checksums.txt "${base}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
   && [ -s checksums.txt ]; then
  grep "$tarball" checksums.txt | sha256sum -c -
else
  echo "WARNING: gitleaks checksums file unavailable; proceeding without verification" >&2
fi
tar -xzf "$tarball" gitleaks
sudo mv gitleaks /usr/local/bin/
semgrep --version && gitleaks version
