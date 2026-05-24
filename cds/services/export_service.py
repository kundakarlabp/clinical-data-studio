import csv
import io
import time
from typing import Any

def now() -> int:
    return int(time.time())

def format_timestamp(ts: int | None) -> str:
    if not ts:
        return "Never"
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

def generate_access_review_csv(conn: Any, study_id: int) -> str:
    query = """
        SELECT users.username, users.display_name, users.role AS global_role,
               study_memberships.role AS study_role, study_memberships.active AS membership_active,
               data_groups.name AS data_group_name, users.active AS user_active,
               (SELECT MAX(created_at) FROM sessions WHERE sessions.user_id = users.id) AS last_login
        FROM users
        JOIN study_memberships ON study_memberships.user_id = users.id
        LEFT JOIN data_groups ON data_groups.id = study_memberships.data_group_id
        WHERE study_memberships.study_id = ?
        ORDER BY users.username
    """
    rows = conn.execute(query, (study_id,)).fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow([
        "Username", "Display Name", "Global Role", "Study Role", 
        "Data Access Group", "Membership Status", "User Status", "Last Login"
    ])
    
    for row in rows:
        r = dict(row)
        writer.writerow([
            r["username"],
            r["display_name"],
            r["global_role"],
            r["study_role"],
            r["data_group_name"] or "None (All Groups)",
            "Active" if r["membership_active"] == 1 else "Inactive",
            "Active" if r["user_active"] == 1 else "Deactivated",
            format_timestamp(r["last_login"])
        ])
        
    return output.getvalue()
