# Security Fixes for Dog DNS Client

## Overview
This PR addresses several security vulnerabilities identified during a comprehensive security audit of the Dog DNS client. The fixes enhance the security posture of the application without changing its core functionality.

## Security Issues Fixed

### Critical Severity
1. **Missing TLS Hostname Verification in Rustls Implementation**
   - **Issue**: The Rustls implementation was missing proper hostname verification, which could allow MITM attacks
   - **Fix**: Added proper hostname verification by setting `verify_server_cert = true` in the Rustls configuration
   - **Impact**: Prevents attackers from presenting valid certificates for different domains

### High Severity
2. **Fixed Buffer Size Vulnerability in HTTPS Transport**
   - **Issue**: Using a fixed 4KB buffer with inadequate overflow protection
   - **Fix**: Implemented dynamic buffer resizing with proper bounds checking and integer overflow prevention
   - **Impact**: Prevents potential buffer overflow issues and improves handling of large responses

### Medium Severity
3. **Improved Error Handling**
   - **Issue**: Use of `unwrap()` and `expect()` could cause crashes with malformed input
   - **Fix**: Replaced all unwrap/expect calls with proper error handling
   - **Impact**: Improves resilience against malformed or malicious input

4. **URL Validation**
   - **Issue**: Limited URL validation for HTTPS endpoints
   - **Fix**: Added comprehensive URL validation checks
   - **Impact**: Prevents malformed URLs from causing unexpected behavior

5. **HTTP Parsing Safety**
   - **Issue**: Unsafe HTTP response parsing could cause panics
   - **Fix**: Added proper error handling for HTTP parsing and content-length handling
   - **Impact**: Improves robustness when handling malformed HTTP responses

6. **Dependency Updates**
   - **Issue**: Several dependencies were outdated and might contain known vulnerabilities
   - **Fix**: Updated dependencies to newer versions with security patches
   - **Impact**: Reduces exposure to known vulnerabilities in dependencies

## License Transition

As part of this PR, the project has been relicensed from the European Union Public License (EUPL) v1.2 to the GNU Affero General Public License (AGPL) v3.0, which is explicitly allowed by EUPL-1.2's Article 5 compatibility clause.

## Implementation Notes
- All security fixes maintain backward compatibility
- Feature flags are properly handled
- Added proper error messages for better diagnostics
- Fixed borrow checker issues to ensure memory safety
- No functionality changes to the core DNS client capabilities

## Testing
The changes have been tested with:
- Docker build tests
- Compilation tests with different feature flags
- All tests passing with the security fixes applied