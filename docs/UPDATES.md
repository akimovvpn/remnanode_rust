# Upstream update PRs

The supported baseline is Remnawave Node **3.4.5**, commit `4009f09de377cd1011fdfd798d6cc9b690637fb8`. `upstream/manifest.json` records SHA256 and file mode for every tracked upstream file, plus resolved versions, URLs and integrity values from its npm lockfile. This covers implementation changes, Docker images, external plugins, SDKs and dependency changes, not only public routes. `upstream/contract.json` contains the 25 public methods/paths and the exact TypeScript contract sources, including request/response schemas. These files are compatibility fixtures; the Rust service does not load or execute TypeScript.

The daily **Track upstream releases** workflow resolves GitHub's latest non-prerelease release, fetches its exact tag into a temporary bare Git repository and compares every tracked file. It never installs dependencies or runs upstream code. A source/contract report is always saved as the `upstream-report` artifact for 30 days, with a summary on the Actions run. A new commit is reported even if its file content is unchanged. The report does not change the supported baseline.

For automated Rust port PRs, add Claude credentials (`CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`, or `ANTHROPIC_API_KEY`), `OPENAI_API_KEY`, or both, as repository Actions secrets. Under **Settings → Actions → General → Workflow permissions**, enable **Allow GitHub Actions to create and approve pull requests**. The workflow requests write permissions only for the final publication job. Enable Actions and scheduled workflows on the default branch; use **Run workflow** to check immediately. With no keys, the report still works and maintainers can port the changes manually. No other service, dashboard or JavaScript runtime is needed by the deployed node.

When there is drift, the pinned official [Claude Code action](https://github.com/anthropics/claude-code-action) prepares a Rust patch first, limited to file edits plus cargo, unit-test and read-only git commands, with no web access and a read-only `GITHUB_TOKEN`. If Claude has no credentials or fails (for example, a usage limit), its partial output is discarded and the pinned [Codex action](https://github.com/openai/codex-action) runs instead, with the workspace permission profile and privilege reduction. Upstream text is explicitly treated as untrusted data. Neither agent receives repository write credentials. A fresh job with no API key validates the patch against an allowlist, rejects workflow/tooling/baseline changes and symlinks, then runs formatting, Clippy, locked Rust tests, Python tooling tests, a real Xray smoke test and a Docker build. Candidate contract fixtures are staged only in that isolated test checkout. After those checks pass, a separate job revalidates the patch, includes the candidate baseline and opens a **draft PR**. That job runs no candidate Rust code or build hooks. There is no automatic merge or deployment. Review behavior, tests and compatibility claims before merging; a green test suite does not prove an arbitrary AI translation complete.

The parser handles the current upstream constant-object syntax without evaluating JavaScript. If upstream changes that syntax or introduces symlinks/submodules, automated porting fails closed and requires a maintainer to inspect and update the tooling. The schema snapshot retains original Zod source rather than an incomplete JSON Schema translation. Reports include full source data for manual inspection.

Manual baseline regeneration, **after implementing and verifying the port**, is:

```sh
python3 scripts/upstream.py baseline /path/to/upstream EXACT_COMMIT RELEASE_TAG
python3 -m unittest discover -s scripts/tests -v
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Review the generated baseline diff with the Rust implementation. Do not refresh it merely to silence a compatibility failure. The baseline command reads committed Git blobs, so local uncommitted upstream files never enter the snapshot. `python3 scripts/upstream.py check --output /tmp/remnanode-report` creates the same report locally without changing the checked-in baseline.

Actions opened by `GITHUB_TOKEN` may not start another `pull_request` workflow automatically. The update workflow runs its own full checks before publication for this reason; maintainers should rerun CI or push their reviewed adjustments when branch protection requires a PR-associated check. Provider/model failures stop the port job and leave the report available. The API call can incur charges only when a changed upstream commit is detected.
