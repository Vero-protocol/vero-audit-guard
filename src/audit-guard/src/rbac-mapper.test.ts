/**
 * Tests for RbacMapper — Issue #13
 *
 * Covers:
 *  - Direct admin role detection (CRITICAL / HIGH)
 *  - Inheritance chain privilege escalation
 *  - Dangerous permission detection
 *  - Least-privilege violation flagging
 *  - Role hierarchy tree construction
 *  - Cycle-safe resolution
 *  - generateReport() output shape
 */

import RbacMapper from "./rbac-mapper";
import type { RbacPolicy, RbacScanResult } from "./rbac-mapper";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const VIEWER_ROLE = {
  id: "viewer",
  name: "Viewer",
  permissions: ["read:contracts"],
};

const EDITOR_ROLE = {
  id: "editor",
  name: "Editor",
  permissions: ["read:contracts", "write:contracts"],
  inherits: ["viewer"],
};

const ADMIN_ROLE = {
  id: "admin",
  name: "Admin",
  permissions: ["read:contracts", "write:contracts", "admin:users"],
  isAdmin: true,
  inherits: ["editor"],
};

const SUPERUSER_ROLE = {
  id: "superuser",
  name: "Superuser",
  permissions: ["*"],
};

const NORMAL_USER = {
  id: "user-1",
  name: "Alice Normal",
  email: "alice@vero.xyz",
  roles: ["viewer"],
};

const EDITOR_USER = {
  id: "user-2",
  name: "Bob Editor",
  email: "bob@vero.xyz",
  roles: ["editor"],
};

const ADMIN_USER = {
  id: "user-3",
  name: "Carol Admin",
  email: "carol@vero.xyz",
  roles: ["admin"],
};

const SUPERUSER_USER = {
  id: "user-4",
  name: "Dave Super",
  email: "dave@vero.xyz",
  roles: ["superuser"],
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeMapper() {
  return new RbacMapper();
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

describe("RbacMapper — input validation", () => {
  it("throws when policy is null", () => {
    const mapper = makeMapper();
    expect(() => mapper.scan(null as any)).toThrow();
  });

  it("throws when roles is missing", () => {
    const mapper = makeMapper();
    expect(() => mapper.scan({ users: [] } as any)).toThrow();
  });

  it("throws when users is missing", () => {
    const mapper = makeMapper();
    expect(() => mapper.scan({ roles: [] } as any)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Safe policy
// ---------------------------------------------------------------------------

describe("RbacMapper — safe policy", () => {
  it("returns SAFE when no users are admin", () => {
    const policy: RbacPolicy = {
      roles: [VIEWER_ROLE, EDITOR_ROLE],
      users: [NORMAL_USER, EDITOR_USER],
    };
    const result = makeMapper().scan(policy);
    expect(result.status).toBe("SAFE");
    expect(result.escalationFindings).toHaveLength(0);
    expect(result.leastPrivilegeViolations).toHaveLength(0);
    expect(result.adminUsers).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Direct admin assignment (isAdmin: true → CRITICAL)
// ---------------------------------------------------------------------------

describe("RbacMapper — direct admin assignment", () => {
  it("flags a user with a direct isAdmin role as CRITICAL", () => {
    const policy: RbacPolicy = {
      roles: [VIEWER_ROLE, EDITOR_ROLE, ADMIN_ROLE],
      users: [ADMIN_USER],
    };
    const result = makeMapper().scan(policy);
    expect(result.status).toBe("VIOLATIONS_FOUND");
    const finding = result.escalationFindings.find(
      (f) => f.severity === "CRITICAL" && f.userId === "user-3"
    );
    expect(finding).toBeDefined();
    expect(finding!.roleId).toBe("admin");
  });

  it("lists the admin user in adminUsers", () => {
    const policy: RbacPolicy = {
      roles: [ADMIN_ROLE],
      users: [ADMIN_USER],
    };
    const result = makeMapper().scan(policy);
    expect(result.adminUsers).toHaveLength(1);
    expect(result.adminUsers[0].id).toBe("user-3");
  });
});

// ---------------------------------------------------------------------------
// Wildcard permission → CRITICAL
// ---------------------------------------------------------------------------

describe("RbacMapper — dangerous wildcard permission", () => {
  it("flags a user with '*' permission as CRITICAL", () => {
    const policy: RbacPolicy = {
      roles: [SUPERUSER_ROLE],
      users: [SUPERUSER_USER],
    };
    const result = makeMapper().scan(policy);
    expect(result.status).toBe("VIOLATIONS_FOUND");
    const finding = result.escalationFindings.find(
      (f) => f.userId === "user-4"
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
  });

  it("flags the user in leastPrivilegeViolations too", () => {
    const policy: RbacPolicy = {
      roles: [SUPERUSER_ROLE],
      users: [SUPERUSER_USER],
    };
    const result = makeMapper().scan(policy);
    const violation = result.leastPrivilegeViolations.find(
      (v) => v.userId === "user-4"
    );
    expect(violation).toBeDefined();
    expect(violation!.excessivePermissions).toContain("*");
  });
});

// ---------------------------------------------------------------------------
// Inheritance chain escalation
// ---------------------------------------------------------------------------

describe("RbacMapper — inheritance chain escalation", () => {
  it("detects escalation when a non-admin role inherits an admin role", () => {
    const escalatorRole = {
      id: "escalator",
      name: "Escalator",
      permissions: ["read:logs"],
      inherits: ["admin"],   // ← inherits the admin role
    };
    const policy: RbacPolicy = {
      roles: [VIEWER_ROLE, EDITOR_ROLE, ADMIN_ROLE, escalatorRole],
      users: [
        {
          id: "user-5",
          name: "Eve Escalated",
          email: "eve@vero.xyz",
          roles: ["escalator"],
        },
      ],
    };
    const result = makeMapper().scan(policy);
    expect(result.status).toBe("VIOLATIONS_FOUND");
    const escalationFinding = result.escalationFindings.find(
      (f) => f.userId === "user-5"
    );
    expect(escalationFinding).toBeDefined();
    expect(escalationFinding!.severity).toBe("HIGH");
    expect(escalationFinding!.reason).toMatch(/inheritance/i);
  });
});

// ---------------------------------------------------------------------------
// Cycle detection (should not throw or infinite-loop)
// ---------------------------------------------------------------------------

describe("RbacMapper — cycle detection", () => {
  it("does not throw on a cyclic inheritance graph", () => {
    const roleA = {
      id: "role-a",
      name: "Role A",
      permissions: ["read:a"],
      inherits: ["role-b"],
    };
    const roleB = {
      id: "role-b",
      name: "Role B",
      permissions: ["read:b"],
      inherits: ["role-a"],  // ← cycle
    };
    const policy: RbacPolicy = {
      roles: [roleA, roleB],
      users: [{ id: "u1", name: "Cycle User", roles: ["role-a"] }],
    };
    expect(() => makeMapper().scan(policy)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Role hierarchy
// ---------------------------------------------------------------------------

describe("RbacMapper — role hierarchy", () => {
  it("builds a hierarchy tree with correct depths", () => {
    const policy: RbacPolicy = {
      roles: [VIEWER_ROLE, EDITOR_ROLE, ADMIN_ROLE],
      users: [],
    };
    const result = makeMapper().scan(policy);
    // admin is a root (nothing inherits it from outside); it should have children
    const adminNode = result.roleHierarchy.find((n) => n.roleId === "admin");
    expect(adminNode).toBeDefined();
    expect(adminNode!.isAdmin).toBe(true);
    // editor is a child of admin
    const editorChild = adminNode!.children.find((n) => n.roleId === "editor");
    expect(editorChild).toBeDefined();
  });

  it("marks roles with admin:* in effective permissions as isAdmin", () => {
    const dangerRole = {
      id: "danger",
      name: "Danger Role",
      permissions: ["admin:*"],
    };
    const policy: RbacPolicy = {
      roles: [dangerRole],
      users: [],
    };
    const result = makeMapper().scan(policy);
    const node = result.roleHierarchy.find((n) => n.roleId === "danger");
    expect(node).toBeDefined();
    expect(node!.isAdmin).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Totals
// ---------------------------------------------------------------------------

describe("RbacMapper — totals", () => {
  it("reports correct totalUsers and totalRoles", () => {
    const policy: RbacPolicy = {
      roles: [VIEWER_ROLE, EDITOR_ROLE, ADMIN_ROLE],
      users: [NORMAL_USER, EDITOR_USER, ADMIN_USER],
    };
    const result = makeMapper().scan(policy);
    expect(result.totalRoles).toBe(3);
    expect(result.totalUsers).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// generateReport
// ---------------------------------------------------------------------------

describe("RbacMapper — generateReport", () => {
  let result: RbacScanResult;

  beforeAll(() => {
    const policy: RbacPolicy = {
      roles: [VIEWER_ROLE, EDITOR_ROLE, ADMIN_ROLE, SUPERUSER_ROLE],
      users: [NORMAL_USER, EDITOR_USER, ADMIN_USER, SUPERUSER_USER],
    };
    result = makeMapper().scan(policy);
  });

  it("produces a markdown report string", () => {
    const report = makeMapper().generateReport(result);
    expect(typeof report).toBe("string");
    expect(report).toContain("## ");
    expect(report).toContain("RBAC");
  });

  it("includes the status in the report", () => {
    const report = makeMapper().generateReport(result);
    expect(report).toContain(result.status);
  });

  it("includes the hierarchy section", () => {
    const report = makeMapper().generateReport(result);
    expect(report).toContain("Role Hierarchy");
  });

  it("includes Admin Users section", () => {
    const report = makeMapper().generateReport(result);
    expect(report).toContain("Admin Users");
  });

  it("includes Privilege Escalation section", () => {
    const report = makeMapper().generateReport(result);
    expect(report).toContain("Privilege Escalation");
  });

  it("includes Least-Privilege section", () => {
    const report = makeMapper().generateReport(result);
    expect(report).toContain("Least-Privilege");
  });

  it("shows SAFE and no findings for a clean policy", () => {
    const clean: RbacPolicy = {
      roles: [VIEWER_ROLE],
      users: [NORMAL_USER],
    };
    const cleanResult = makeMapper().scan(clean);
    const report = makeMapper().generateReport(cleanResult);
    expect(report).toContain("SAFE");
    expect(report).toContain("No privilege escalation paths detected");
  });
});
