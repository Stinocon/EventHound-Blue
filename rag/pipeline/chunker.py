from __future__ import annotations

# Approximation: ~4 characters per token. Enough to size chunks
# without depending on the tokenizer of a specific embedding provider.
CHARS_PER_TOKEN = 4


def chunk_text(text: str, max_tokens: int = 400, overlap: int = 80) -> list[str]:
    """Splits the text into chunks with overlap, respecting paragraph boundaries.

    Paragraphs (separated by a blank line) are accumulated as long as they fit
    within the limit; a paragraph longer than the limit is cut into character
    windows. Between one chunk and the next, an overlap tail is carried over so
    context spanning the cut point isn't lost.
    """
    text = (text or "").strip()
    if not text:
        return []

    max_chars = max(1, max_tokens * CHARS_PER_TOKEN)
    # The overlap is capped at half the window: if overlap approaches max_tokens, the cut
    # step (max_chars - overlap_chars) would collapse toward 1 character, generating ~one
    # chunk per character (duplicate explosion on a long paragraph). Capping at max_chars//2
    # guarantees a step of at least half the window and doesn't affect sane configs (default
    # overlap 80 / max 400 -> 320 < 800).
    overlap_chars = max(0, min(overlap * CHARS_PER_TOKEN, max_chars // 2))

    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    buf = ""

    for para in paragraphs:
        if len(para) > max_chars:
            if buf:
                chunks.append(buf)
                # Carries over a tail of the buffer as overlap into the first chunk of
                # the long paragraph, consistently with the other branches.
                tail = buf[-overlap_chars:] if overlap_chars else ""
                buf = ""
                if tail:
                    para = f"{tail}\n\n{para}"
            step = max(1, max_chars - overlap_chars)
            for i in range(0, len(para), step):
                chunks.append(para[i:i + max_chars])
            continue

        if not buf:
            buf = para
        elif len(buf) + len(para) + 2 <= max_chars:
            buf = f"{buf}\n\n{para}"
        else:
            chunks.append(buf)
            # The overlap tail must be capped at the remaining space, otherwise tail+para could
            # exceed max_chars and a chunk beyond the max_tokens contract would be emitted. para <= max_chars here.
            room = max_chars - len(para) - 2
            tail = buf[-min(overlap_chars, room):] if (overlap_chars and room > 0) else ""
            buf = f"{tail}\n\n{para}" if tail else para

    if buf:
        chunks.append(buf)
    return chunks
