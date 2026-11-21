"""Reference fix: stored XSS.

Why the hole existed
    To keep line breaks, the note body was turned into HTML with Markup(), which
    switched off escaping for the whole note. Anything the author typed, including
    <script>, became part of the page for every reader.

Why this fix works
    The body is escaped first, so it is plain text as far as the browser is
    concerned. Only then are the newlines replaced by <br> tags that we add
    ourselves. The order matters: escape the untrusted part, then add trusted markup.

The secure pattern
    Store what the user typed, escape it when you render it. Do not try to strip
    or blocklist "dangerous" tags: there are too many ways to run script
    (onerror=, <svg onload>, javascript: links). If users really need rich text,
    run it through a maintained allowlist sanitizer. For this case CSS alone
    would also do: `white-space: pre-line` keeps line breaks with no HTML at all.
"""

from markupsafe import Markup, escape


def render_note(body):
    """Return a note's body as HTML, keeping the author's line breaks."""
    return escape(body).replace("\n", Markup("<br>"))
