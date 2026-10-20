# CLAUDE.md - Next.js project

<!-- Lean on purpose (about 100 lines). Long rule files get skimmed and cost tokens on every message.
     Fill in the [BRACKETS], delete lines that do not apply, and keep it short.
     Rules that MUST hold (secrets, deletes, force-push) are enforced by hooks, not by this file. -->

## Project
[One sentence: what this app does and who uses it.]
Stack: Next.js ([App Router | Pages Router]), TypeScript, [Tailwind | CSS Modules], [Prisma | Drizzle | Supabase], [NextAuth | Clerk | Supabase Auth].

## Commands
- Install: `[npm install]`
- Dev server: `[npm run dev]`
- Build: `[npm run build]`
- Lint: `[npm run lint]`
- Type check: `[npx tsc --noEmit]`
- Test: `[npm test]`
- A task is NOT done until build, type check and tests pass. Run them and report the real output.

## Working style
- Read the files involved before editing. Do not guess at code you have not opened.
- Smallest change that solves the task. No drive-by refactors, renames or formatting changes.
- Prefer editing existing files to creating new ones. Reuse existing components and helpers: search first.
- Match the code style already in the repo (naming, folder layout, imports). Do not add a new library when the stack already has one that does the job.
- If the task is unclear or has two reasonable readings, ask one short question before building.
- If something fails twice, stop and use `/stuck`. Do not keep trying variations.

## Next.js rules
- Server Components by default. Add `"use client"` only when you need state, effects, event handlers or browser APIs, and push it as far down the tree as possible.
- Fetch data in Server Components or route handlers, not in `useEffect`, unless it must be client-side.
- Do not import server-only code (DB client, secrets) into a client component. Mark server-only modules with `import "server-only"`.
- Mutations go through server actions or route handlers that validate input on the server. Never trust the client.
- Use `next/image` and `next/link`; use `next/font` for fonts.
- Do not set `export const dynamic = "force-dynamic"` or disable caching to "fix" a bug without saying so and explaining why.

## Environment variables and secrets
- Anything named `NEXT_PUBLIC_*` is shipped to every visitor's browser. NEVER put a secret there.
- Secrets live in `.env.local` (git-ignored). Read them with `process.env.NAME` on the server only.
- Never print, log, commit or paste the value of a secret. Never edit `.env*` files; tell me which variable is needed and I will add it.
- Add every new variable to `.env.example` with a fake placeholder value.
- Supabase: the `service_role` / secret key is server-only. The anon / publishable key is the only one allowed in client code.

## Database
- Schema changes go through migrations (`[prisma migrate dev | drizzle-kit generate]`), never by editing the live database by hand.
- Never run a reset, drop, truncate or `--force` command. Ask me first, and say which database it would hit.
- Always scope updates and deletes with a WHERE clause. Say how many rows you expect to change.
- Assume the connection string in `.env.local` may point at real data unless I say it is a throwaway.

## Auth and security
- Check the user's session AND their permission to the specific record on the server, in every route handler and server action.
- Validate all input with `[zod]` at the boundary. Return generic error messages; do not leak stack traces.
- No `dangerouslySetInnerHTML` with user content. No `eval`. No disabling TypeScript or ESLint rules to silence an error.

## Tests
- Add or update a test for each behaviour change. Prefer testing behaviour, not implementation details.
- Never delete, skip (`.skip`, `xit`) or loosen a test to make it pass. If a test looks wrong, tell me why.
- Do not mock the thing you are testing.

## Git
- Never commit unless I ask. When I do: one focused commit, message explains why.
- Never force-push, `git reset --hard`, or `git clean` without asking. Never use `--no-verify`.
- Do not touch `main`/`master` directly; work on a feature branch.

## Project map
- `app/` routes and layouts - `[describe]`
- `components/` shared UI - `[describe]`
- `lib/` helpers, DB and API clients - `[describe]`
- `[other important folder]` - `[describe]`

## Known gotchas
- [Things that have already cost you time, e.g. "Stripe webhook route must read the raw body".]
- [Add one line each time Claude makes the same mistake twice.]

## Compaction
When context is compacted, keep: the goal, files changed, failing tests with their exact errors, and decisions made. Drop long command output.
