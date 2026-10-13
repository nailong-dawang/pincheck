# pincheck

Find the unpinned actions in your GitHub workflows.

**查查你 GitHub Actions 里没锁死的 action。**

---

## Why / 为什么

Oct 2026: malicious commits were pushed straight to `colinhacks/zod` on
GitHub. npm-side scanning held the line — but your CI is the other half of
the supply chain. A floating `uses: actions/checkout@v5` re-resolves on
**every run**, and a hijacked tag — the exact play used against tj-actions
and others — quietly turns your pipeline into someone else's runner.

**Tags are promises, SHAs are facts.** pincheck tells you which one your
workflows are built on.

2026 年 10 月：有人直接往 `colinhacks/zod` 的 GitHub 仓库推了恶意
commit。npm 侧的扫描守住了这一头——但你的 CI 是供应链的另一半。
一句浮动的 `uses: actions/checkout@v5` **每次运行都会重新解析**，
一个被劫持的 tag（tj-actions 等事件的同款手法）就能悄悄把你的
pipeline 变成别人的矿机。

**tag 是承诺，SHA 是事实。** pincheck 告诉你，你的 workflow 到底建在哪个上面。

## What it does / 干什么

Scans `.github/workflows/*.yml|*.yaml`, extracts every `uses:` ref, and
grades how many are pinned to an immutable commit SHA.

扫描 `.github/workflows/*.yml|*.yaml`，抓出所有 `uses:` 引用，
看有多少是锁死在不可变的 commit SHA 上的。

| Grade | Meaning / 含义 |
|-------|----------------|
| A | pinned to a full 40-char commit SHA / 锁死在完整 commit SHA |
| B | short SHA — immutable but collision-prone / 短 SHA（不可变但可碰撞） |
| C | mutable tag — retaggable by the publisher / 可变 tag（发布者可重打） |
| F | floating branch (`main`, `latest`…) — re-resolves every run / 浮动分支 |
| – | local action (`./...`) — nothing to pin / 本地 action |

```
$ python3 pincheck.py ./myrepo
pincheck: auditing 23 action refs in 3 workflow files ...

  SHA-pinned (A)      : 18
  short-SHA (B)       : 0
  mutable tag (C)     : 4
  floating branch (F) : 1
  local (-)           : 0

  CI trust grade        : B — mostly pinned — a few mutable refs left

Unpinned refs (worst first):
  [F] .github/workflows/deploy.yml:31  some-org/custom@main
       ↳ floating branch — re-resolves on every run
  [C] .github/workflows/ci.yml:7  actions/checkout@v5
       ↳ mutable tag 'v5' — retaggable by the action's publisher

Fix: pin to the action's current commit SHA, e.g.
  uses: some-org/custom@<40-char-sha>  # main
  (keep the tag in a trailing comment so humans still see the version)
```

## Usage / 用法

```bash
python3 pincheck.py [repo_root]   # audit / 审计
python3 pincheck.py --strict .    # exit 1 unless grade is A / 非 A 则报错退出
```

Stdlib only — drop it into CI as a gate:

```yaml
- name: CI must be pin-locked
  run: python3 tools/pincheck.py --strict .
```

**The fix pattern** — pin the SHA, keep the tag for humans:

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v5.0.1
```

## License

MIT — do whatever, just pin your SHAs.
