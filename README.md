TokenTwin Checker

Multi-User Broken Access Control (BAC) & IDOR Testing Extension for Burp
Suite

TokenTwin Checker is a Burp Suite extension designed to automate
authorization testing across multiple authenticated users. It helps
security researchers and bug bounty hunters quickly identify Broken
Access Control (BAC), IDOR, and horizontal privilege escalation
vulnerabilities by replaying requests using different authentication
contexts.

Features

-   Multi-user authentication profiles
-   Cookie-based authentication support
-   Custom authentication header support
-   All-vs-All testing matrix
-   Automatic BAC / IDOR detection
-   Baseline comparison mode
-   Smart filtering for dynamic responses
-   Custom Ignore Regex support
-   Risk classification engine
-   CSV export
-   Side-by-side request comparison
-   Built-in Proof-of-Concept viewer
-   Supports REST and JSON APIs

Supported Vulnerability Classes

-   Broken Access Control (BAC)
-   Insecure Direct Object References (IDOR)
-   Horizontal Privilege Escalation
-   Missing Authorization Checks
-   Improper Ownership Validation
-   Authorization Bypass

Testing Modes

Baseline Mode

Reduces false positives and improves comparison accuracy.

All vs All Matrix Mode

Automatically tests every user against every other user.

Usage

1.  Install the extension in Burp Suite.
2.  Add multiple authenticated user profiles.
3.  Send interesting requests to TokenTwin.
4.  Click Run Test.
5.  Review findings.

Recommended Targets

-   REST APIs
-   GraphQL APIs
-   SPAs
-   Mobile APIs
-   JSON APIs

Requirements

-   Burp Suite Professional
-   Java 17+

Disclaimer

Use only against systems you are authorized to test.

License

MIT License
