ROLES = ("admin", "manager", "officer")
ROLE_LABELS = {"admin": "Admin", "manager": "Manager", "officer": "Officer"}
DEFAULT_ROLE = "officer"  # lowest-privilege role; used for self-registration

USER_STATUSES = ("Pending", "Approved", "Rejected", "Disabled")

TASK_STATUSES = ("Pending", "In Progress", "Submitted", "Approved", "Rejected")
PRIORITIES = ("Low", "Medium", "High")

USERS_PER_PAGE = 10
TASKS_PER_PAGE = 10
LOGS_PER_PAGE = 15
NOTIFICATIONS_PER_PAGE = 10

# Runtime settings an admin can change (Admin > Settings). Anything not
# listed here can never be written to the settings table.
SETTING_DEFAULTS = {
    "manager_can_manage_officers": "0",  # safe default: off
}
