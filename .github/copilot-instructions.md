# Repository Instructions for AI Coding Agents

## Project Workflow (OpenSpec)

This repository uses **OpenSpec** for all non-trivial changes.

Standard flow:
1. **Planning** → `/opsx-propose` or `/opsx-update` (prefer a strong reasoning model)
2. **Implementation** → `/opsx-apply` (prefer a strong coding/agent model)
3. **Archive** → `/opsx-archive` when the change is complete

Never start coding a significant feature without an approved OpenSpec change that contains:
- `proposal.md`
- `specs/`
- `design.md` (when architectural decisions are needed)
- `tasks.md`

## Preferred Model Roles (local Ollama)

- **Planning / Propose / Update**: DeepSeek-R1:32b (or Qwen3.8)
  - Focus on clear requirements, scenarios, design decisions, and actionable tasks.
  - Do **not** write application code during planning.

- **Implementation / Apply**: Flint
  - Follow the existing plan strictly.
  - Make precise, minimal changes that match project conventions.
  - Mark tasks complete only when fully done.

## Coding Guidelines

- Prefer small, focused, reviewable changes.
- Match existing code style, naming, and patterns.
- Read relevant existing code before editing.
- Prefer clarity and correctness over cleverness.
- Do not invent new requirements or expand the scope beyond the approved plan.
- When a task is ambiguous or blocked, stop and ask instead of guessing.

## OpenSpec Artifacts

When creating or updating artifacts:
- Write requirements as testable SHALL statements.
- Use concrete Given/When/Then scenarios.
- Keep tasks small, ordered, and verifiable.
- Call out assumptions and open questions explicitly.

When implementing (`/opsx-apply`):
- Work through `tasks.md` in order.
- Verify implementation against the scenarios in `specs/`.
- Prefer focused verification over large unrelated refactoring.
