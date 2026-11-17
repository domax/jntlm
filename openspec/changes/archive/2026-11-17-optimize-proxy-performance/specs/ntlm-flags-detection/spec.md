# Spec Delta

## MODIFIED Requirements

### Requirement: Detection result logging
The system SHALL log the accepted flags at INFO, as `0x`-prefixed 8-digit hex, together with the
parent proxy. It SHALL log each rejected candidate and its reason at DEBUG without imposing
material per-request overhead after the result is cached.

#### Scenario: Successful detection log
- **WHEN** detection accepts flags `0x00088205` for parent `proxy.example.com:8080`
- **THEN** an INFO log line contains `0x00088205` and `proxy.example.com:8080`

#### Scenario: Cached detection
- **GIVEN** detection has completed and the active parent is unchanged
- **WHEN** later requests obtain the cached flags
- **THEN** no additional probe or candidate-rejection logging occurs
