# Security policy

## Status

Atrium is in **early alpha and is not for production use**. It has not undergone an independent security audit, and no security guarantees are made at this stage. See the README's Project status section for what has and has not been verified.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository (the **Security** tab → **Report a vulnerability**). Please do not open a public issue for a vulnerability.

Useful reports include:

- The affected build (the CalVer stamp, e.g. 261118_1820) and component (installer, server, client, shell)
- A description of the issue and its impact
- Reproduction steps or a proof of concept

## Supported versions

Only the latest build is supported. Installs are total rebuilds by design; there is no patching of older builds.

## Known by-design items

- The seed administrator password is an operator-set configuration value: the shipped configuration template carries a placeholder, and the installer's configuration gate refuses to proceed until the operator replaces it. The first sign-in forces a password change before anything else is reachable. The placeholder being visible in the shipped template is by design and is not a vulnerability: it cannot be deployed as-is.
- Install-time configuration defaults include placeholder hostnames for internal services (backup target, certificate authority). These are configuration values, not credentials.
