# SpecMon Docs

This directory contains the SpecMon documentation site built with Astro + Starlight.

## Requirements

- Node.js and pnpm (recommended: run `nix develop` from the repo root to get the toolchain)

## Commands

Run these from `docs/`:

```bash
pnpm install
pnpm dev
pnpm build
pnpm preview
```

## Project Structure

```
public/                 # Static assets
src/content/docs/       # Documentation content (Markdown/MDX)
src/components/         # Custom Starlight components
src/styles/             # Global styles
astro.config.mjs        # Site configuration
```

## Notes

- Use `pnpm-lock.yaml` as the lockfile source of truth.
- Starlight routes map to files under `src/content/docs/`.
