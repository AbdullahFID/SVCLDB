# Run this after creating the empty repo at:
#   https://github.com/new
# Owner: AbdullahDaGoat
# Repo name: svcldb
# Visibility: Private
# DO NOT initialize with README/gitignore/license (we already have those)

cd C:\Users\abdul\Desktop\svcldb

# 1. Wire up the remote
git remote add origin https://github.com/AbdullahDaGoat/svcldb.git 2>&1

# 2. Push
git push -u origin main 2>&1

Write-Host ""
Write-Host "Done. Verify:"
git remote -v
git log --oneline -3
