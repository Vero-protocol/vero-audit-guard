/**
 * Security Tips Library
 * Provides automated security training tips for developers
 */

export interface SecurityTip {
  id: string;
  title: string;
  content: string;
}

export const SECURITY_TIPS: SecurityTip[] = [
  {
    id: "SEC_TIP_SECRET_MGMT",
    title: "Secret Management",
    content: "Never commit secrets, API keys, or private keys to the repository. Use environment variables or a dedicated secret management service like AWS Secrets Manager or GitHub Secrets."
  },
  {
    id: "SEC_TIP_DEP_SECURITY",
    title: "Dependency Security",
    content: "Regularly audit your dependencies for known vulnerabilities using `npm audit` or `yarn audit`. Pin your dependency versions to avoid unexpected breaking changes and potential supply chain attacks."
  },
  {
    id: "SEC_TIP_INPUT_VAL",
    title: "Input Validation",
    content: "Always validate and sanitize user input to prevent common vulnerabilities like Cross-Site Scripting (XSS) and SQL Injection. Never trust data coming from the client-side."
  },
  {
    id: "SEC_TIP_LEAST_PRIV",
    title: "Principle of Least Privilege",
    content: "Grant only the minimum permissions necessary for a user or system to perform its function. This limits the potential impact of a security breach."
  },
  {
    id: "SEC_TIP_SEC_COMM",
    title: "Secure Communication",
    content: "Always use encrypted protocols like HTTPS for transmitting sensitive data. Ensure that SSL/TLS certificates are valid and up-to-date."
  },
  {
    id: "SEC_TIP_ERR_HANDLING",
    title: "Secure Error Handling",
    content: "Avoid displaying detailed error messages to users, as they can reveal sensitive information about your system's architecture. Log detailed errors internally for debugging purposes."
  },
  {
    id: "SEC_TIP_AUTH_N_AUTHZ",
    title: "Authentication & Authorization",
    content: "Implement robust authentication and authorization mechanisms. Use well-established libraries and frameworks instead of building your own security logic from scratch."
  },
  {
    id: "SEC_TIP_DATA_MIN",
    title: "Data Minimization",
    content: "Only collect and store the data that is absolutely necessary for your application. Reducing the amount of sensitive data you hold minimizes the risk in case of a data breach."
  }
];
