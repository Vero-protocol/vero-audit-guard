/**
 * RBAC Mapper — Access Control Audit
 *
 * Issue #13: feat: implement access control audit
 *
 * Maps admin roles, visualises the role-inheritance hierarchy, detects
 * privilege-escalation paths, and flags least-privilege violations.
 *
 * Design follows the same conventions as the other audit-guard modules:
 *  - A primary class with a `scan()` method returning a typed result
 *  - A `generateReport()` method rendering a human-readable markdown summary
 *  - Pure computation (no I/O, no global state) so it is trivially testable
 *  - Optional config with env-var fallback where appropriate
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type RbacSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** A single permission string, e.g. "read:contracts" or "admin:*" */
export type Permission = string;

/**
 * A role definition.  `inherits` is an optional list of *role IDs* whose
 * permissions this role transitively receives (depth-first, cycle-safe).
 */
export interface RbacRole {
  id: string;
  name: string;
  permissions: Permission[];
  /** Role IDs this role inherits from (hierarchy edges, parent → child). */
  inherits?: string[];
  /** Mark the role as an admin role explicitly. */
  isAdmin?: boolean;
}

/** A principal (user / service account) and the roles it holds. */
export interface RbacUser {
  id: string;
  name: string;
  email?: string;
  /** Role IDs assigned directly to this user. */
  roles: string[];
}

/** The full RBAC policy document fed into the mapper. */
export interface RbacPolicy {
  roles: RbacRole[];
  users: RbacUser[];
}

// ---------------------------------------------------------------------------
// Finding types
// ---------------------------------------------------------------------------

export interface PrivilegeEscalationFinding {
  userId: string;
  userName: string;
  roleId: string;
  roleName: string;
  /** Human-readable explanation of the escalation path. */
  reason: string;
  severity: RbacSeverity;
  remediation: string;
}

export interface LeastPrivilegeViolation {
  userId: string;
  userName: string;
  /** Permissions granted to the user that exceed the minimum required. */
  excessivePermissions: Permission[];
  severity: RbacSeverity;
  remediation: string;
}

// ---------------------------------------------------------------------------
// Hierarchy types
// ---------------------------------------------------------------------------

/** A node in the resolved role-inheritance tree. */
export interface RoleHierarchyNode {
  roleId: string;
  roleName: string;
  /** Depth from the root of the hierarchy (root = 0). */
  depth: number;
  children: RoleHierarchyNode[];
  /** Fully resolved permissions including those inherited from parents. */
  effectivePermissions: Permission[];
  isAdmin: boolean;
}

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------

export interface RbacScanResult {
  status: "SAFE" | "VIOLATIONS_FOUND";
  escalationFindings: PrivilegeEscalationFinding[];
  leastPrivilegeViolations: LeastPrivilegeViolation[];
  /** Role hierarchy forest (one tree per top-level root role). */
  roleHierarchy: RoleHierarchyNode[];
  /** Users that hold at least one admin role. */
  adminUsers: RbacUser[];
  totalUsers: number;
  totalRoles: number;
  summary: string;
  scanTimestamp: string;
}

export interface RbacScanOptions {
  /**
   * Maximum inheritance depth to follow before treating a role cycle as
   * an escalation finding.  Default: 10.
   */
  maxInheritanceDepth?: number;
  /**
   * When true (default), any user with a direct or inherited admin role
   * generates a finding.
   */
  flagAdminUsers?: boolean;
  /**
   * Permissions that are considered "dangerous" (grant admin-level access
   * even without an `isAdmin` flag).  Can be extended per deployment.
   */
  dangerousPermissions?: Permission[];
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_DEPTH = 10;
const DEFAULT_DANGEROUS_PERMISSIONS: readonly Permission[] = Object.freeze([
  "*",
  "admin:*",
  "assign:roles",
  "manage:permissions",
  "manage:users",
  "impersonate:users",
  "sudo",
]);

const ADMIN_ROLE_NAME_RE = /\b(admin|superuser|root|owner|god-mode)\b/i;

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<RbacSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------

/**
 * RBAC Mapper
 *
 * Accepts a `RbacPolicy` (roles + users) and produces a `RbacScanResult`
 * that lists privilege-escalation paths, least-privilege violations, and a
 * visual role-hierarchy tree.
 */
export class RbacMapper {
  private readonly maxDepth: number;
  private readonly dangerousPermissions: Set<Permission>;

  constructor(options: RbacScanOptions = {}) {
    this.maxDepth = options.maxInheritanceDepth ?? DEFAULT_MAX_DEPTH;
    this.dangerousPermissions = new Set([
      ...DEFAULT_DANGEROUS_PERMISSIONS,
      ...(options.dangerousPermissions ?? []),
    ]);
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Run the full RBAC audit over the supplied policy and return a
   * `RbacScanResult`.
   */
  public scan(policy: RbacPolicy, _options: RbacScanOptions = {}): RbacScanResult {
    if (!policy || !Array.isArray(policy.roles) || !Array.isArray(policy.users)) {
      throw new Error("RbacMapper.scan: policy must have 'roles' and 'users' arrays");
    }

    const roleMap = this.buildRoleMap(policy.roles);
    const effectivePermMap = this.resolveAllPermissions(roleMap);
    const hierarchy = this.buildHierarchy(policy.roles, roleMap, effectivePermMap);
    const adminRoleIds = this.resolveAdminRoleIds(roleMap, effectivePermMap);

    const escalationFindings = this.detectPrivilegeEscalation(
      policy.users,
      roleMap,
      effectivePermMap,
      adminRoleIds
    );
    const leastPrivilegeViolations = this.detectLeastPrivilegeViolations(
      policy.users,
      effectivePermMap
    );

    const adminUsers = policy.users.filter((u) =>
      u.roles.some((rId) => adminRoleIds.has(rId))
    );

    const allFindings = [
      ...escalationFindings,
      ...leastPrivilegeViolations,
    ];
    const status: RbacScanResult["status"] =
      allFindings.length > 0 ? "VIOLATIONS_FOUND" : "SAFE";

    const summary =
      status === "SAFE"
        ? "✅ No RBAC violations detected — least privilege appears enforced"
        : `❌ ${escalationFindings.length} privilege escalation finding(s), ` +
          `${leastPrivilegeViolations.length} least-privilege violation(s)`;

    return {
      status,
      escalationFindings,
      leastPrivilegeViolations,
      roleHierarchy: hierarchy,
      adminUsers,
      totalUsers: policy.users.length,
      totalRoles: policy.roles.length,
      summary,
      scanTimestamp: new Date().toISOString(),
    };
  }

  /**
   * Render a human-readable markdown report from a `RbacScanResult`.
   */
  public generateReport(result: RbacScanResult): string {
    const emoji = result.status === "SAFE" ? "✅" : "❌";
    let report = `## ${emoji} RBAC Access Control Audit\n\n`;
    report += `**Status:** ${result.status}\n\n`;
    report += `**Scanned at:** ${result.scanTimestamp}\n\n`;
    report += `**Roles:** ${result.totalRoles}  |  **Users:** ${result.totalUsers}\n\n`;
    report += `${result.summary}\n\n`;

    // Role hierarchy tree
    report += "---\n\n";
    report += "### 🗂️ Role Hierarchy\n\n";
    if (result.roleHierarchy.length === 0) {
      report += "_No roles defined._\n\n";
    } else {
      report += this.renderHierarchy(result.roleHierarchy, 0);
      report += "\n";
    }

    // Admin users
    report += "---\n\n";
    report += `### 👑 Admin Users (${result.adminUsers.length})\n\n`;
    if (result.adminUsers.length === 0) {
      report += "_No users with admin roles detected._\n\n";
    } else {
      for (const u of result.adminUsers) {
        const email = u.email ? ` <${u.email}>` : "";
        report += `- **${u.name}**${email} — roles: \`${u.roles.join(", ")}\`\n`;
      }
      report += "\n";
    }

    // Privilege escalation findings
    report += "---\n\n";
    report += `### 🚨 Privilege Escalation Findings (${result.escalationFindings.length})\n\n`;
    if (result.escalationFindings.length === 0) {
      report += "_No privilege escalation paths detected._\n\n";
    } else {
      const sorted = [...result.escalationFindings].sort(
        (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
      );
      for (const f of sorted) {
        report += `- **${f.roleId}** [${f.severity}]\n`;
        report += `  User **${f.userName}** (\`${f.userId}\`): ${f.reason}\n`;
        report += `  _Remediation:_ ${f.remediation}\n\n`;
      }
    }

    // Least privilege violations
    report += "---\n\n";
    report += `### ⚠️ Least-Privilege Violations (${result.leastPrivilegeViolations.length})\n\n`;
    if (result.leastPrivilegeViolations.length === 0) {
      report += "_No least-privilege violations detected._\n\n";
    } else {
      for (const v of result.leastPrivilegeViolations) {
        report += `- **${v.userName}** (\`${v.userId}\`) [${v.severity}]\n`;
        report += `  Excessive permissions: \`${v.excessivePermissions.join("`, `")}\`\n`;
        report += `  _Remediation:_ ${v.remediation}\n\n`;
      }
    }

    return report;
  }

  // -------------------------------------------------------------------------
  // Internal: role resolution
  // -------------------------------------------------------------------------

  /** Build an O(1)-lookup map of role ID → RbacRole. */
  private buildRoleMap(roles: RbacRole[]): Map<string, RbacRole> {
    const map = new Map<string, RbacRole>();
    for (const role of roles) {
      map.set(role.id, role);
    }
    return map;
  }

  /**
   * Resolve the full effective permission set for every role, following
   * `inherits` edges with DFS and cycle detection.
   *
   * Returns a map of role ID → Set<Permission>.
   */
  private resolveAllPermissions(
    roleMap: Map<string, RbacRole>
  ): Map<string, Set<Permission>> {
    const cache = new Map<string, Set<Permission>>();

    const resolve = (id: string, visited: Set<string>, depth: number): Set<Permission> => {
      if (cache.has(id)) return cache.get(id)!;
      if (visited.has(id) || depth > this.maxDepth) {
        // Cycle or depth limit — return own permissions only to be safe
        return new Set(roleMap.get(id)?.permissions ?? []);
      }

      const role = roleMap.get(id);
      if (!role) return new Set();

      visited.add(id);
      const perms = new Set<Permission>(role.permissions);

      for (const parentId of role.inherits ?? []) {
        const parentPerms = resolve(parentId, new Set(visited), depth + 1);
        for (const p of parentPerms) perms.add(p);
      }

      cache.set(id, perms);
      return perms;
    };

    for (const id of roleMap.keys()) {
      resolve(id, new Set(), 0);
    }

    return cache;
  }

  /**
   * Collect all role IDs that are considered "admin" — either explicitly
   * via `isAdmin: true`, via a dangerous permission in their effective
   * permission set, or via a name that matches the admin regex.
   */
  private resolveAdminRoleIds(
    roleMap: Map<string, RbacRole>,
    effectivePermMap: Map<string, Set<Permission>>
  ): Set<string> {
    const adminIds = new Set<string>();

    for (const [id, role] of roleMap) {
      if (role.isAdmin) {
        adminIds.add(id);
        continue;
      }
      if (ADMIN_ROLE_NAME_RE.test(role.name) || ADMIN_ROLE_NAME_RE.test(id)) {
        adminIds.add(id);
        continue;
      }
      const perms = effectivePermMap.get(id) ?? new Set();
      for (const p of perms) {
        if (this.dangerousPermissions.has(p)) {
          adminIds.add(id);
          break;
        }
      }
    }

    return adminIds;
  }

  // -------------------------------------------------------------------------
  // Internal: hierarchy builder
  // -------------------------------------------------------------------------

  /**
   * Build the role hierarchy forest.  Top-level roles are those that are
   * NOT listed as children by any other role.
   */
  private buildHierarchy(
    roles: RbacRole[],
    roleMap: Map<string, RbacRole>,
    effectivePermMap: Map<string, Set<Permission>>
  ): RoleHierarchyNode[] {
    // Roles that appear in someone else's inherits list = not a root
    const nonRoots = new Set<string>();
    for (const role of roles) {
      for (const parentId of role.inherits ?? []) {
        nonRoots.add(parentId);
      }
    }

    // Root roles = roles that are not a child of anyone
    const roots = roles.filter((r) => !nonRoots.has(r.id));

    const buildNode = (id: string, depth: number, visited: Set<string>): RoleHierarchyNode => {
      const role = roleMap.get(id)!;
      const effectivePermissions = Array.from(effectivePermMap.get(id) ?? []).sort();
      const isAdmin =
        !!role.isAdmin ||
        ADMIN_ROLE_NAME_RE.test(role.name) ||
        effectivePermissions.some((p) => this.dangerousPermissions.has(p));

      const children: RoleHierarchyNode[] = [];
      if (!visited.has(id)) {
        const nextVisited = new Set(visited).add(id);
        for (const childId of role.inherits ?? []) {
          if (roleMap.has(childId) && depth < this.maxDepth) {
            children.push(buildNode(childId, depth + 1, nextVisited));
          }
        }
      }

      return { roleId: id, roleName: role.name, depth, children, effectivePermissions, isAdmin };
    };

    return roots.map((r) => buildNode(r.id, 0, new Set()));
  }

  /** Render a hierarchy node list as an indented markdown list. */
  private renderHierarchy(nodes: RoleHierarchyNode[], depth: number): string {
    let out = "";
    const indent = "  ".repeat(depth);
    for (const node of nodes) {
      const adminTag = node.isAdmin ? " 👑" : "";
      const permLabel =
        node.effectivePermissions.length > 0
          ? ` _(${node.effectivePermissions.length} permission${node.effectivePermissions.length !== 1 ? "s" : ""})_`
          : "";
      out += `${indent}- \`${node.roleId}\` **${node.roleName}**${adminTag}${permLabel}\n`;
      if (node.children.length > 0) {
        out += this.renderHierarchy(node.children, depth + 1);
      }
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Internal: privilege escalation detection
  // -------------------------------------------------------------------------

  private detectPrivilegeEscalation(
    users: RbacUser[],
    roleMap: Map<string, RbacRole>,
    effectivePermMap: Map<string, Set<Permission>>,
    adminRoleIds: Set<string>
  ): PrivilegeEscalationFinding[] {
    const findings: PrivilegeEscalationFinding[] = [];

    for (const user of users) {
      for (const roleId of user.roles) {
        const role = roleMap.get(roleId);
        if (!role) continue;

        // Vector 1: direct admin role assignment
        if (adminRoleIds.has(roleId) && role.isAdmin) {
          findings.push({
            userId: user.id,
            userName: user.name,
            roleId,
            roleName: role.name,
            reason: `Direct assignment of admin role \`${roleId}\` (isAdmin: true).`,
            severity: "CRITICAL",
            remediation:
              "Verify this admin assignment is intentional, time-bound, and audited. " +
              "Prefer granting scoped roles over blanket admin access.",
          });
          continue;
        }

        // Vector 3: dangerous permissions in effective permission set (check before name match
        // so that wildcard permissions always surface as CRITICAL)
        const effectivePerms = effectivePermMap.get(roleId) ?? new Set();
        const dangerous = Array.from(effectivePerms).filter((p) =>
          this.dangerousPermissions.has(p)
        );
        if (dangerous.length > 0) {
          const hasCritical =
            dangerous.includes("*") ||
            dangerous.includes("sudo") ||
            dangerous.includes("admin:*") ||
            dangerous.includes("impersonate:users");
          findings.push({
            userId: user.id,
            userName: user.name,
            roleId,
            roleName: role.name,
            reason:
              `Role \`${roleId}\` grants dangerous permission(s): ${dangerous.map((p) => `\`${p}\``).join(", ")}.`,
            severity: hasCritical ? "CRITICAL" : "HIGH",
            remediation:
              "Replace wildcard / admin permissions with fine-grained scoped permissions " +
              "following the principle of least privilege.",
          });
          continue;
        }

        // Vector 2: role name matches admin pattern (no dangerous perm found above)
        if (adminRoleIds.has(roleId) && ADMIN_ROLE_NAME_RE.test(role.name)) {
          findings.push({
            userId: user.id,
            userName: user.name,
            roleId,
            roleName: role.name,
            reason: `Role name \`${role.name}\` matches admin pattern — admin-level access implied.`,
            severity: "HIGH",
            remediation:
              "Rename the role to something more granular and strip any unnecessary permissions.",
          });
          continue;
        }

        // Vector 4: inherited admin role escalation
        const escalationChain = this.findAdminInheritanceChain(
          roleId,
          roleMap,
          adminRoleIds,
          [],
          new Set()
        );
        if (escalationChain.length > 0) {
          const chain = [roleId, ...escalationChain].join(" → ");
          findings.push({
            userId: user.id,
            userName: user.name,
            roleId,
            roleName: role.name,
            reason: `Privilege escalation via inheritance chain: \`${chain}\`.`,
            severity: "HIGH",
            remediation:
              "Break the inheritance chain by splitting roles into least-privilege " +
              "components and removing the admin role from the inheritance path.",
          });
        }
      }
    }

    return findings;
  }

  /**
   * DFS over the role inheritance graph to find whether any ancestor role
   * is an admin role.  Returns the chain of role IDs that leads to an admin
   * role, or an empty array if none is found.
   */
  private findAdminInheritanceChain(
    roleId: string,
    roleMap: Map<string, RbacRole>,
    adminRoleIds: Set<string>,
    chain: string[],
    visited: Set<string>
  ): string[] {
    if (visited.has(roleId)) return [];
    visited.add(roleId);

    const role = roleMap.get(roleId);
    if (!role) return [];

    for (const parentId of role.inherits ?? []) {
      if (adminRoleIds.has(parentId)) {
        return [...chain, parentId];
      }
      const deeper = this.findAdminInheritanceChain(
        parentId,
        roleMap,
        adminRoleIds,
        [...chain, parentId],
        new Set(visited)
      );
      if (deeper.length > 0) return deeper;
    }

    return [];
  }

  // -------------------------------------------------------------------------
  // Internal: least-privilege violation detection
  // -------------------------------------------------------------------------

  private detectLeastPrivilegeViolations(
    users: RbacUser[],
    effectivePermMap: Map<string, Set<Permission>>
  ): LeastPrivilegeViolation[] {
    const violations: LeastPrivilegeViolation[] = [];

    for (const user of users) {
      // Collect all effective permissions across all assigned roles
      const allPerms = new Set<Permission>();
      for (const roleId of user.roles) {
        const perms = effectivePermMap.get(roleId) ?? new Set();
        for (const p of perms) allPerms.add(p);
      }

      // Flag excessive permissions: wildcards or broad admin scopes
      const excessive = Array.from(allPerms).filter(
        (p) =>
          p === "*" ||
          p.endsWith(":*") ||
          this.dangerousPermissions.has(p)
      );

      if (excessive.length > 0) {
        const hasCritical = excessive.some((p) => p === "*" || p === "admin:*" || p === "sudo");
        violations.push({
          userId: user.id,
          userName: user.name,
          excessivePermissions: excessive.sort(),
          severity: hasCritical ? "CRITICAL" : "HIGH",
          remediation:
            "Replace wildcard/admin permissions with scoped permissions covering only " +
            "the resources and actions this user legitimately needs.",
        });
      }
    }

    return violations;
  }
}

export default RbacMapper;
