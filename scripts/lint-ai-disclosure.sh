#!/bin/bash
# Lint script to check for AI disclosure consistency
# Ensures has_ai: true posts have corresponding .ai-disclosure.md files
# And that .ai-disclosure.md files have corresponding has_ai: true posts

POSTS_DIR="_posts"
ERRORS=0

echo "🔍 Linting AI disclosure files..."
echo ""

# Check 1: Posts with has_ai: true but no corresponding .ai-disclosure.md
echo "Checking for posts with has_ai: true but no .ai-disclosure.md..."
for post in "$POSTS_DIR"/*.md; do
    # Skip ai-disclosure files
    [[ "$post" == *".ai-disclosure.md" ]] && continue

    filename=$(basename "$post")

    if grep -q "has_ai: true" "$post"; then
        disclosure_file="${post%.md}.ai-disclosure.md"

        if [ ! -f "$disclosure_file" ]; then
            echo "  ❌ $filename has 'has_ai: true' but missing $(basename "$disclosure_file")"
            ((ERRORS++))
        fi
    fi
done

# Check 2: .ai-disclosure.md files without corresponding has_ai: true posts
echo ""
echo "Checking for .ai-disclosure.md files without has_ai: true posts..."
for disclosure in "$POSTS_DIR"/*.ai-disclosure.md; do
    [ -f "$disclosure" ] || continue

    post_file="${disclosure%.ai-disclosure.md}.md"

    if [ ! -f "$post_file" ]; then
        echo "  ❌ $(basename "$disclosure") exists but corresponding post not found"
        ((ERRORS++))
    elif ! grep -q "has_ai: true" "$post_file"; then
        echo "  ❌ $(basename "$disclosure") exists but post doesn't have 'has_ai: true'"
        ((ERRORS++))
    fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ All AI disclosure files are consistent!"
    exit 0
else
    echo "❌ Found $ERRORS disclosure inconsistency/inconsistencies"
    exit 1
fi
