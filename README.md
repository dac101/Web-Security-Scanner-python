# Web-Security-Scanner
GitHub Repository Description:

This project provides an automated web security scanning tool designed to identify common vulnerabilities in web applications. It includes various security tests such as missing security headers, HTTP verb tampering, cookie flag analysis, SSL/TLS cipher strength evaluation, and HTTP header information disclosure detection.

The script is built using Python and leverages libraries such as requests for HTTP interactions, ssl for encryption testing, and cryptography for certificate analysis. Key features include:
	•	Security Header Analysis: Detects missing HTTP security headers (e.g., HSTS, CSP, X-Frame-Options).
	•	HTTP Verb Tampering: Tests for unauthorized HTTP methods that might expose security loopholes.
	•	Cookie Security Checks: Identifies missing security flags such as Secure, HttpOnly, and SameSite.
	•	SSL/TLS Security Audit: Evaluates cipher suites to detect weak encryption algorithms.
	•	Information Disclosure Tests: Analyzes response headers for potential data leaks.

This repository is ideal for penetration testers, security professionals, and developers aiming to enhance the security posture of their web applications.
