"""
Backend pagination helper.
==========================
paginate() runs the COUNT query to find the total number of matching
rows, then re-runs the main query with LIMIT/OFFSET appended so SQLite
itself only returns the one page of rows that's needed - the full result
set is never loaded into Python or sent to the browser.
"""

import math


def paginate(conn, base_query, count_query, params, page, per_page):
    total = conn.execute(count_query, params).fetchone()[0]
    total_pages = max(1, math.ceil(total / per_page)) if per_page else 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    rows = conn.execute(base_query + " LIMIT ? OFFSET ?", params + (per_page, offset)).fetchall()

    start = 0 if total == 0 else offset + 1
    end = min(offset + per_page, total)

    info = {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1,
        "next_page": page + 1,
        "start": start,
        "end": end,
        "page_numbers": page_window(page, total_pages),
    }
    return rows, info


def page_window(current_page, total_pages, spread=2):
    """Page numbers to display, with None marking a '...' gap -
    e.g. [1, None, 4, 5, 6, None, 12] - so a huge page count doesn't
    render dozens of page buttons."""
    if total_pages <= 7:
        return list(range(1, total_pages + 1))

    pages = {1, total_pages, current_page}
    for offset in range(1, spread + 1):
        pages.add(current_page - offset)
        pages.add(current_page + offset)
    pages = sorted(p for p in pages if 1 <= p <= total_pages)

    windowed = []
    previous = None
    for p in pages:
        if previous is not None and p - previous > 1:
            windowed.append(None)
        windowed.append(p)
        previous = p
    return windowed
