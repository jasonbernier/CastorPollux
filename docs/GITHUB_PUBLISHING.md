# Publish CastorPollux to GitHub

This source tree is prepared for a GitHub repository. It intentionally omits the bundled engines and release EXE. The current EXE is roughly 0.86 GB, above GitHub's 100 MiB regular repository file limit; upload it as a **Release asset**. GitHub allows individual release assets under 2 GiB. See [repository file limits](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github) and [release asset limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

## 1. Review the source package

From this folder, run:

```powershell
Get-ChildItem -Recurse -File | Sort-Object Length -Descending | Select-Object -First 20 FullName,Length
git status --short
```

Check that `work/archives/`, `work/runtime/`, investigations, logs, private binaries, and `outputs/CastorPollux.exe` are absent. Read `README.md`, credits, and the commercial audit. Choose and add a license for CastorPollux's original code only after deciding its distribution terms; the present package grants no open-source license for that code. Third-party licenses remain independent.

## 2. Create the repository and push source

Install [Git](https://git-scm.com/download/win) and [GitHub CLI](https://cli.github.com/) if needed. Sign in with `gh auth login`. In PowerShell, inside this source folder:

```powershell
git init -b main
git add .
git status --short
git commit -m "CastorPollux 1.0.0 source and documentation"
gh repo create CastorPollux --private --source . --remote origin --push
```

Use `OWNER/CastorPollux` in `gh repo create` for an organization or non-default owner. Start private while reviewing the original-code license and third-party redistribution obligations; the owner can change visibility later. If a GitHub repository already exists, set its HTTPS remote and push instead:

```powershell
git remote add origin https://github.com/OWNER/CastorPollux.git
git push -u origin main
```

Inspect the staged file list before committing. `.gitignore` helps prevent mistakes, but it does not remove a file already committed; use `git rm --cached` if an unwanted file was staged. If a secret was committed, rotate it and follow GitHub's history-removal guidance rather than only deleting the latest copy.

## 3. Attach the large Windows release

Complete the release verification and license review first. After building, compare `CastorPollux-SHA256.txt` to the EXE in the build's `outputs` folder. Set `$releaseDir` to that absolute folder. Then create the release from the repository owner checkout:

```powershell
$releaseDir = 'E:\path\to\CastorPollux\outputs'
gh release create v1.0.0 `
  (Join-Path $releaseDir 'CastorPollux.exe') `
  (Join-Path $releaseDir 'CastorPollux-SHA256.txt') `
  (Join-Path $releaseDir 'CastorPollux-Package.zip') `
  --title "CastorPollux 1.0.0" `
  --notes-file .\docs\RELEASE_NOTES.md `
  --draft
```

Review the draft page, source archive, asset names and SHA-256, license notices, and signature status. Publish the draft in GitHub when ready. `CastorPollux-Package.zip` contains the same EXE plus docs and notices; if it exceeds the per-asset 2 GiB limit, omit it and attach separate smaller files. Do not place the EXE in normal Git history or use Git LFS as a workaround for this release flow. [GitHub release instructions](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository) explain the web and CLI alternatives.

## 4. Future updates

Commit source changes to `main`, run focused tests and an engine smoke test, update `docs/RELEASE_NOTES.md` and inventories, tag a new version, then attach newly built binaries to a new release. From the build workspace, run `python work/build_github_archive.py` to regenerate the deterministic source-only upload ZIP. Keep example configurations free of private paths and tokens. Only describe an EXE or update as signed after the publisher signature has been applied and verified.
