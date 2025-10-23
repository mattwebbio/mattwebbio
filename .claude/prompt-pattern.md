# Blog Post AI Disclosure Pattern

This documents the pattern for including AI-generated content disclosure files with blog posts while keeping them out of the published site.

## File Structure

For each blog post that contains AI-generated content:

```
_posts/
  ├── YYYY-MM-DD-post-title.md               # Blog post (published)
  └── YYYY-MM-DD-post-title.ai-disclosure.md # AI disclosure (not published)
```

## Setup

1. **Create the disclosure file** in `_posts/` with the same date prefix as your post (contains prompts, notes, etc.)
2. **Add front matter property** to your post:

```yaml
---
layout: post
title: "Your Post Title"
date: 2025-10-23
has_ai: true
---
```

3. **No other changes needed** - The template automatically:
   - Detects the `has_ai: true` property
   - Generates the disclosure message
   - Links to the corresponding `.ai-disclosure.md` file on GitHub

## How It Works

- The `.ai-disclosure.md` files are excluded from Jekyll's build process via `_config.yml`
- They remain in the source repository (accessible to anyone who clones it)
- Search engines don't index them (they don't appear in the published site)
- The disclosure link points to the GitHub markdown file in the repo
- Readers who care about the prompts can find them via the link

## Linting

The project includes automatic linting to ensure consistency:

- **Pre-commit hook**: Runs `scripts/lint-ai-disclosure.sh` before each commit
- **Pre-push hook**: Runs the same check before pushing to prevent bad commits
- **GitHub Actions**: Runs the lint check on all pull requests and pushes to main

The lint script checks for:
- ✅ Posts with `has_ai: true` but missing corresponding `.ai-disclosure.md` file
- ✅ `.ai-disclosure.md` files without a corresponding `has_ai: true` post

Run manually anytime with:
```bash
bash scripts/lint-ai-disclosure.sh
```

## Example

See: `_posts/2025-10-23-ghidra-auto-namer-with-claude-code.md` and `_posts/2025-10-23-ghidra-auto-namer-with-claude-code.ai-disclosure.md`
