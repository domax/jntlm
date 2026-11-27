# Spec Delta

## ADDED Requirements

### Requirement: Open-relay exposure warning
The system SHALL log a WARN at startup when the listener is bound to an address that is not a
loopback address (including the wildcard address) while client authentication is disabled. The
warning SHALL name the bound address and suggest enabling `jntlm.client-auth.enabled` or binding to
`127.0.0.1`. Startup SHALL still succeed.

#### Scenario: Wildcard bind without client auth
- **GIVEN** `jntlm.listen-address: 0.0.0.0` and client authentication disabled
- **WHEN** jntlm starts
- **THEN** a WARN log entry names `0.0.0.0` and mentions `jntlm.client-auth.enabled`
- **AND** the listener starts normally

#### Scenario: Loopback bind
- **GIVEN** `jntlm.listen-address: 127.0.0.1` and client authentication disabled
- **WHEN** jntlm starts
- **THEN** no exposure warning is logged

#### Scenario: Non-loopback bind with client auth
- **GIVEN** `jntlm.listen-address: 0.0.0.0` and client authentication enabled
- **WHEN** jntlm starts
- **THEN** no exposure warning is logged
