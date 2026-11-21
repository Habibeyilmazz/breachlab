"""Reference fix: reflected XSS.

Why the hole existed
    The heading was assembled with an f-string and then wrapped in Markup(), which
    tells the template engine "this is finished HTML, do not escape it". The search
    term inside it was therefore sent to the browser as markup, script tags included.

Why this fix works
    Markup.format() escapes every argument before inserting it, so `<` arrives as
    `&lt;` and the browser shows the text instead of parsing it. Only the part we
    wrote ourselves (the <strong> tags) is real HTML.

The secure pattern
    Escape on output, for the context you are writing into. Let the template
    engine's auto-escaping do the work and treat every Markup(), `|safe` or
    innerHTML as a place that needs a second look. Never mark a string as safe
    after user input has been mixed into it. A Content-Security-Policy that
    forbids inline scripts is a good second layer, not a replacement.
"""

from markupsafe import Markup


def results_heading(query, count):
    """Return the HTML heading shown above help search results."""
    return Markup("{} result(s) for <strong>{}</strong>").format(count, query)
