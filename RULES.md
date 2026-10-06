# Rules for keeping this record

These hold for anyone who writes to this repository, people and agents alike.

1. **Only `tools/record.py` writes `MANIFEST.csv`.** Never edit it by hand, and never open and save it in a spreadsheet: that rewrites line endings and breaks the chain.
2. **Append only.** Never edit, reorder or delete a row or a proof. A mistake is answered with a new row: a withdrawal (only before the first outcome read) or a new version that names the one it supersedes.
3. **No force push, ever.** Never rebase, amend or reset anything already pushed. The branch rule on `main` blocks force pushes and branch deletion for everyone; never remove or relax it.
4. **Hashes only.** Sealed files, the text of the sealing rules and anything from the ledger stay outside this folder. `.gitignore` admits only the files listed in it; read `git status` before every commit. The check fails if anything else is tracked.
5. **A list is sealed only at a full gate.** `seal-read` needs `--gate K/K`, where K is the number of checks in the rules in force; the tool refuses anything less.
6. **Keep every sealed file the tool names.** Each `.sealed` file is the exact file its row proves. Losing one makes that row uncheckable.
7. **One commit per write, pushed at once,** with the message the tool prints.
8. **Upgrade proofs** a few hours after each stamp: `python tools/record.py upgrade`, then `python tools/record.py verify --bitcoin`, then commit "upgrade proofs" and push.
9. **If the check goes red, stop sealing.** Read its FAIL line. Never repair the manifest by editing it. A fault in the tool is fixed in the tool, in a new commit that leaves every row and proof as it was.
10. **Settings that stay on:** repository public; issues, wiki and projects off; branch rule "append-only main" active with no bypass; commits under the account's GitHub no-reply email address.
