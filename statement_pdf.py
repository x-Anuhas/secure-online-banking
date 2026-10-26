"""Generate signed, in-memory PDF statements from a user's ledger history."""

import hashlib
import hmac
import json
import sqlite3
import calendar
from datetime import date, datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from security import decrypt_sensitive_value


def generate_monthly_statement(
    connection: sqlite3.Connection,
    user_id: int,
    year: int,
    month: int,
    signing_key: str,
) -> tuple[BytesIO, str]:
    """Build a monthly statement PDF and its HMAC verification digest."""
    first_day = date(year, month, 1)
    next_month = date(year + (month == 12), month % 12 + 1, 1)
    start_time = calendar.timegm(
        datetime(year, month, 1, tzinfo=timezone.utc).utctimetuple()
    )
    end_time = calendar.timegm(
        datetime(next_month.year, next_month.month, 1, tzinfo=timezone.utc).utctimetuple()
    )
    account = connection.execute(
        """
        SELECT full_name, username, account_number, balance_cents,
               opening_balance_cents
        FROM users WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    if account is None:
        raise LookupError("The statement account no longer exists.")

    opening_activity = connection.execute(
        """
        SELECT COALESCE(SUM(CASE WHEN direction = 'credit' THEN amount_cents
                                 ELSE -amount_cents END), 0) AS net
        FROM ledger_entries WHERE user_id = ? AND created_at < ?
        """,
        (user_id, start_time),
    ).fetchone()["net"]
    entries = connection.execute(
        """
        SELECT l.id, l.direction, l.amount_cents, l.created_at,
               t.id AS transfer_id, t.reference, t.reference_ciphertext,
               CASE WHEN l.user_id = t.sender_id THEN recipient.username
                    ELSE sender.username END AS counterparty
        FROM ledger_entries AS l
        JOIN transfers AS t ON t.id = l.transfer_id
        JOIN users AS sender ON sender.id = t.sender_id
        JOIN users AS recipient ON recipient.id = t.recipient_id
        WHERE l.user_id = ? AND l.created_at >= ? AND l.created_at < ?
        ORDER BY l.created_at, l.id
        """,
        (user_id, start_time, end_time),
    ).fetchall()
    entries = [
        {
            **dict(entry),
            "reference": (
                decrypt_sensitive_value(entry["reference_ciphertext"])
                if entry["reference_ciphertext"] is not None
                else entry["reference"]
            ),
        }
        for entry in entries
    ]
    opening_balance = account["opening_balance_cents"] + opening_activity
    total_credits = sum(
        entry["amount_cents"] for entry in entries if entry["direction"] == "credit"
    )
    total_debits = sum(
        entry["amount_cents"] for entry in entries if entry["direction"] == "debit"
    )
    closing_balance = opening_balance + total_credits - total_debits
    signed_data = {
        "account_number": account["account_number"],
        "period": first_day.strftime("%Y-%m"),
        "opening_balance_cents": opening_balance,
        "closing_balance_cents": closing_balance,
        "transactions": [
            {
                "id": entry["id"],
                "transfer_id": entry["transfer_id"],
                "direction": entry["direction"],
                "amount_cents": entry["amount_cents"],
                "created_at": entry["created_at"],
                "counterparty": entry["counterparty"],
                "reference": entry["reference"],
            }
            for entry in entries
        ],
    }
    canonical_data = json.dumps(
        signed_data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    verification_hash = hmac.new(
        signing_key.encode("utf-8"), canonical_data, hashlib.sha256
    ).hexdigest()

    output = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="StatementTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#12324a"),
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="StatementSmall",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#43576a"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="StatementRight",
            parent=styles["BodyText"],
            alignment=TA_RIGHT,
        )
    )

    def draw_page(canvas, document) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#d5e0e8"))
        canvas.line(document.leftMargin, 0.62 * inch, letter[0] - document.rightMargin, 0.62 * inch)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#43576a"))
        canvas.drawString(
            document.leftMargin,
            0.42 * inch,
            f"Verification HMAC-SHA256: {verification_hash}",
        )
        canvas.drawRightString(
            letter[0] - document.rightMargin,
            0.42 * inch,
            f"Page {document.page}",
        )
        canvas.restoreState()

    document = BaseDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.82 * inch,
        title=f"FinBest statement {first_day:%B %Y}",
        author="FinBest",
    )
    frame = Frame(
        document.leftMargin,
        document.bottomMargin,
        document.width,
        document.height,
        id="statement",
    )
    document.addPageTemplates([PageTemplate(id="statement", frames=[frame], onPage=draw_page)])

    story = [
        Paragraph("FINBEST", styles["StatementTitle"]),
        Paragraph(f"Monthly account statement · {first_day:%B %Y}", styles["Heading2"]),
        Paragraph(
            f"<b>Account holder:</b> {account['full_name']} "
            f"({account['username']})<br/>"
            f"<b>Account number:</b> {account['account_number']}<br/>"
            f"<b>Period:</b> {first_day:%Y-%m-%d} through "
            f"{date(year, month, calendar.monthrange(year, month)[1]):%Y-%m-%d}",
            styles["BodyText"],
        ),
        Spacer(1, 14),
    ]
    summary_rows = [
        ["Opening balance", "Credits", "Debits", "Closing balance"],
        [
            f"${opening_balance / 100:,.2f}",
            f"${total_credits / 100:,.2f}",
            f"${total_debits / 100:,.2f}",
            f"${closing_balance / 100:,.2f}",
        ],
    ]
    summary = Table(summary_rows, colWidths=[1.8 * inch] * 4)
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12324a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5e0e8")),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.extend([summary, Spacer(1, 18), Paragraph("Transactions", styles["Heading2"])])
    transaction_rows = [["Date (UTC)", "Type", "Counterparty", "Reference", "Amount"]]
    for entry in entries:
        amount = entry["amount_cents"] / 100
        signed_amount = f"{'+' if entry['direction'] == 'credit' else '-'}${amount:,.2f}"
        transaction_rows.append(
            [
                date.fromtimestamp(entry["created_at"]).strftime("%Y-%m-%d"),
                entry["direction"].title(),
                Paragraph(str(entry["counterparty"]), styles["StatementSmall"]),
                Paragraph(str(entry["reference"] or "—"), styles["StatementSmall"]),
                signed_amount,
            ]
        )
    if not entries:
        transaction_rows.append(["No transactions for this period.", "", "", "", ""])
    transactions = Table(
        transaction_rows,
        colWidths=[0.9 * inch, 0.65 * inch, 1.25 * inch, 2.15 * inch, 1.15 * inch],
        repeatRows=1,
        hAlign="LEFT",
    )
    transactions.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf1f5")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#12324a")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d5e0e8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (-1, 1), (-1, -1), "RIGHT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend(
        [
            transactions,
            Spacer(1, 12),
            Paragraph(
                "This statement describes simulated activity. The footer HMAC is "
                "generated by the application and can be checked by an authorized "
                "verifier holding the application signing key.",
                styles["StatementSmall"],
            ),
        ]
    )
    document.build(story)
    output.seek(0)
    return output, verification_hash
