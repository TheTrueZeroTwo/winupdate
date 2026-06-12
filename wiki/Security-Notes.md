# Security Notes

This project is intentionally convenient for remote support, but it executes code from a raw web source. Treat the source URL as trusted code.

Recommended MSP practices:

- Host the source on infrastructure you control.
- Use HTTPS.
- Restrict write access to the source repo.
- Review changes before they reach `main`.
- Keep CI tests enabled.
- Keep logs available for technician review.
- Avoid copying repo scripts to client computers.

The helper is not a replacement for RMM tooling. It is a lightweight helper for remote sessions and controlled scheduled maintenance tasks.
