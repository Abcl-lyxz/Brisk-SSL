---
description: End-of-session handoff - update ROADMAP checkboxes, rewrite .claude/state/handoff.md, commit and push. Use when the user is done for now (จบ / พอแค่นี้ / stop / handoff).
---
# Session handoff

1. `git status` and `git log --oneline -15` to see what this session did.
2. Tick `docs/ROADMAP.md` boxes only for work verified green on **all** archs
   (`python tools/dev.py test --arch all`).
3. Rewrite `.claude/state/handoff.md` (max 40 lines, it is injected into the next session):
   - **Done** this session (commits)
   - **In progress** (file:line and exactly what is left)
   - **Next up** (the exact next task, so `/next` can start without questions)
   - **Decisions / gotchas** learned (anything not obvious from the code)
4. Commit `docs: handoff YYYY-MM-DD` and `git push` (plain push; never force).
5. Reply with a 3-line summary: done, next, anything the user must do.
