# Repository History Cleanup

If live secrets were ever committed to this repository, they must be removed from git history. Simply deleting them in a later commit is **not sufficient** — secrets remain accessible in previous commits.

## When to Use This Procedure

- A secret was committed to `.env.development`, `.env.production`, `.env.example`, or any other tracked file.
- A secret was committed in source code, documentation, or test files.
- You are unsure whether a secret was ever committed.

## Before You Begin

1. **Assume the secret is compromised.** Treat it as exposed and rotate it immediately.
2. **Coordinate with the team.** History rewriting changes commit SHAs and requires force-push.
3. **Create a backup.** Clone the repository to a safe location before rewriting history.

## Tools

Choose one of the following tools:

- **[git-filter-repo](https://github.com/newren/git-filter-repo)** (recommended) — fast, Python-based, actively maintained.
- **[BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)** — fast, Java-based, simpler for common cases.

`git filter-branch` is **not recommended** — it is slow, error-prone, and deprecated by the Git project.

## Procedure Using git-filter-repo

### 1. Install git-filter-repo

```bash
# macOS
brew install git-filter-repo

# Ubuntu / Debian
sudo apt-get install git-filter-repo

# Python pip
pip install git-filter-repo
```

### 2. Clone a Fresh Copy

```bash
git clone --mirror https://github.com/nyashahama/healthcare-access-connector-backend.git repo-mirror.git
cd repo-mirror.git
```

### 3. Remove the Secret

Replace a specific string (e.g., a leaked password or API key):

```bash
git filter-repo --replace-text <(echo 'LEAKED_SECRET==>REDACTED')
```

Replace an entire file (e.g., `.env.production` that contained live secrets):

```bash
git filter-repo --path .env.production --invert-paths
```

### 4. Verify the Rewrite

```bash
# Confirm the secret no longer appears in history
git log --all --full-history -- .env.production
git log --all -S 'LEAKED_SECRET'

# If either returns results, the secret is still present — stop and investigate.
```

### 5. Force-Push the Clean History

```bash
# WARNING: This changes every commit SHA. All open PRs and local clones must be rebased.
git push --force --all
git push --force --tags
```

### 6. Notify the Team

Everyone with a local clone must:

```bash
# Re-clone fresh (safest)
git clone https://github.com/nyashahama/healthcare-access-connector-backend.git

# Or rebase their local branches onto the new history
git fetch origin
git rebase origin/main
```

### 7. Rotate the Secret

Even after history cleanup, treat the secret as exposed:

1. Generate a new secret at the provider.
2. Update deployment environment variables.
3. Revoke the old secret.

## Procedure Using BFG Repo-Cleaner

### 1. Download BFG

```bash
wget https://repo1.maven.org/maven2/com/madgag/bfg/1.14.0/bfg-1.14.0.jar
```

### 2. Clone a Fresh Copy

```bash
git clone --mirror https://github.com/nyashahama/healthcare-access-connector-backend.git repo-mirror.git
cd repo-mirror.git
```

### 3. Remove the Secret

Create a file `secrets.txt` containing the secret string(s) to remove, one per line:

```
LEAKED_SECRET
ANOTHER_LEAKED_KEY
```

Run BFG:

```bash
java -jar bfg-1.14.0.jar --replace-text secrets.txt repo-mirror.git
```

### 4. Clean Reflog and Dangling Objects

```bash
cd repo-mirror.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### 5. Verify and Force-Push

Follow steps 4–7 from the git-filter-repo procedure above.

## Verification Checklist

- [ ] The secret string returns no results in `git log -S 'SECRET'`.
- [ ] The secret file returns no results in `git log --all --full-history -- path/to/file`.
- [ ] The old secret has been rotated and revoked.
- [ ] All team members have been notified to re-clone or rebase.
- [ ] CI/CD pipelines and deployment platforms have been updated with the new secret.

## Prevention

- Always run `go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v` before committing.
- Use pre-commit hooks to block secrets.
- Never paste real secrets into source files, even "temporarily."

See also:
- [Secret Ownership](secret-ownership.md)
- [Secret Rotation Guide](secrets-rotation.md)
