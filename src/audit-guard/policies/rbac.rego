# RBAC Access Control Policy
# Issue #13: feat: implement access control audit
#
# Evaluates a role-based access control policy document for
# privilege escalation and least-privilege violations.
#
# Expected input shape:
#   {
#     "roles": [{ "id": "...", "name": "...", "permissions": [...], "isAdmin": bool, "inherits": [...] }],
#     "users": [{ "id": "...", "name": "...", "email": "...", "roles": [...] }]
#   }

package rbac.compliance

import data.lib.severity

# ---------------------------------------------------------------------------
# Helper: set of all role IDs that are explicitly marked as admin
# ---------------------------------------------------------------------------
admin_role_ids[id] {
  role := input.roles[_]
  role.isAdmin == true
  id := role.id
}

# Helper: set of dangerous permissions
dangerous_permissions := {
  "*",
  "admin:*",
  "assign:roles",
  "manage:permissions",
  "manage:users",
  "impersonate:users",
  "sudo"
}

# ---------------------------------------------------------------------------
# Helper: resolve all permissions for a given role (own + inherited, 1 level)
# Note: OPA does not support recursive rules with full DFS natively,
# so we resolve one level of inheritance here. Deeper chains are caught
# by the TypeScript RbacMapper which does full DFS.
# ---------------------------------------------------------------------------
role_permissions[role_id] = perms {
  role := input.roles[_]
  role.id == role_id
  own := {p | p := role.permissions[_]}
  inherited := {p |
    parent_id := role.inherits[_]
    parent := input.roles[_]
    parent.id == parent_id
    p := parent.permissions[_]
  }
  perms := own | inherited
}

# ---------------------------------------------------------------------------
# DENY: user has direct admin role (isAdmin: true)
# ---------------------------------------------------------------------------
deny[msg] {
  user := input.users[_]
  role_id := user.roles[_]
  admin_role_ids[role_id]
  role := input.roles[_]
  role.id == role_id
  msg := {
    "rule": "DIRECT_ADMIN_ASSIGNMENT",
    "severity": severity.HIGH,
    "message": sprintf("User '%s' has direct admin role assignment", [user.name]),
    "detail": sprintf("Role '%s' grants admin privileges to user '%s' (%s)", [role_id, user.name, user.id])
  }
}

# ---------------------------------------------------------------------------
# DENY: user holds a role with a dangerous (wildcard / admin) permission
# ---------------------------------------------------------------------------
deny[msg] {
  user := input.users[_]
  role_id := user.roles[_]
  perms := role_permissions[role_id]
  dangerous_perm := perms & dangerous_permissions
  count(dangerous_perm) > 0
  role := input.roles[_]
  role.id == role_id
  msg := {
    "rule": "DANGEROUS_PERMISSION_GRANTED",
    "severity": severity.CRITICAL,
    "message": sprintf("User '%s' holds dangerous permission(s) via role '%s'", [user.name, role_id]),
    "detail": sprintf("Dangerous permissions: %v", [dangerous_perm])
  }
}

# ---------------------------------------------------------------------------
# DENY: role inherits directly from an admin role (1-level escalation)
# ---------------------------------------------------------------------------
deny[msg] {
  user := input.users[_]
  role_id := user.roles[_]
  role := input.roles[_]
  role.id == role_id
  parent_id := role.inherits[_]
  admin_role_ids[parent_id]
  msg := {
    "rule": "INHERITED_ADMIN_ESCALATION",
    "severity": severity.HIGH,
    "message": sprintf("User '%s' escalates to admin via role inheritance", [user.name]),
    "detail": sprintf("Role '%s' inherits from admin role '%s'", [role_id, parent_id])
  }
}

# ---------------------------------------------------------------------------
# WARNING: more than one admin role assigned to a single user
# ---------------------------------------------------------------------------
warning[msg] {
  user := input.users[_]
  admin_roles := [r | r := user.roles[_]; admin_role_ids[r]]
  count(admin_roles) > 1
  msg := {
    "rule": "MULTIPLE_ADMIN_ROLES",
    "severity": severity.MEDIUM,
    "message": sprintf("User '%s' holds multiple admin roles", [user.name]),
    "detail": sprintf("Admin roles: %v", [admin_roles])
  }
}

# ---------------------------------------------------------------------------
# WARNING: role has more than 10 permissions (over-provisioning signal)
# ---------------------------------------------------------------------------
warning[msg] {
  role := input.roles[_]
  count(role.permissions) > 10
  msg := {
    "rule": "ROLE_OVER_PROVISIONED",
    "severity": severity.LOW,
    "message": sprintf("Role '%s' has more than 10 permissions", [role.name]),
    "detail": sprintf("Permission count: %d. Consider splitting into more granular roles.", [count(role.permissions)])
  }
}

# ---------------------------------------------------------------------------
# Compliance summary
# ---------------------------------------------------------------------------
compliant {
  count(deny) == 0
}

rbac_summary[msg] {
  v := count(deny)
  w := count(warning)
  v == 0
  w == 0
  msg := {
    "status": "SAFE",
    "message": "✅ RBAC policy is compliant — least privilege enforced.",
    "violations": 0,
    "warnings": 0
  }
}

rbac_summary[msg] {
  v := count(deny)
  w := count(warning)
  v > 0
  msg := {
    "status": "VIOLATIONS_FOUND",
    "message": sprintf("❌ RBAC violations found: %d violation(s), %d warning(s)", [v, w]),
    "violations": v,
    "warnings": w
  }
}

rbac_summary[msg] {
  v := count(deny)
  w := count(warning)
  v == 0
  w > 0
  msg := {
    "status": "WARNINGS",
    "message": sprintf("⚠️  No violations but %d RBAC warning(s)", [w]),
    "violations": 0,
    "warnings": w
  }
}
