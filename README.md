# JWT Manager for Delphi

A simple JWT (JSON Web Token) library for Delphi with no external dependencies.

## Features

### JWT Operations
- Create tokens with custom claims
- Validate tokens with HMAC-SHA256 signature verification
- Refresh tokens while preserving claims
- Support for standard claims (exp, iat, nbf, iss, aud, sub, jti)
- Extract tokens from HTTP Authorization headers

### Security Protection
- Rate limiting: configurable attempts per time window
- Algorithm validation: prevents "none" algorithm attacks
- Key validation: enforces 32+ character keys with character diversity
- Constant-time signature comparison prevents timing attacks
- Configurable token size limits (default 8KB)
- Clock skew tolerance for time synchronization
- Detects tokens issued in the future
- Secure memory zeroing of sensitive data

### Implementation Features
- Thread-safe operations with critical sections
- Security event logging with timestamps
- Memory leak detection via FastMM5 integration
- Configurable validation parameters

## Requirements

- Delphi 10.3 Rio or later
- FastMM5 (included in examples)
- Standard Delphi units: System.JSON, System.NetEncoding

## Installation

1. Add `GJWTManager.pas` to your project
2. Include required units:
```pascal
uses
  GJWTManager, System.JSON, System.SysUtils;
```

## Quick Start

### Basic Usage

```pascal
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
begin
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create(
      'your-secure-secret-key-minimum-32-characters-long',
      'YourApp',           // Issuer
      60,                  // Expiration in minutes
      'api.yourapp.com'    // Audience (optional)
    );
    
    // Create token
    Token := Manager.CreateToken('user123');
    
    // Validate token
    if Manager.ValidateToken(Token, JWT) then
    begin
      Writeln('Subject: ', JWT.Subject);
      Writeln('Expires: ', DateTimeToStr(JWT.ExpirationTime));
    end
    else
      Writeln('Invalid token: ', JWT.ErrorMessage);
  finally
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(Manager) then
      Manager.Free;
  end;
end;
```

### Custom Claims

```pascal
var
  CustomClaims: TJSONObject;
  JWT: TJWTToken;
  Token: string;
begin
  CustomClaims := nil;
  JWT := nil;
  try
    CustomClaims := TJSONObject.Create;
    CustomClaims.AddPair('role', 'admin');
    CustomClaims.AddPair('department', 'IT');
    
    Token := Manager.CreateToken('jane.doe', CustomClaims);
    
    if Manager.ValidateToken(Token, JWT) then
    begin
      Writeln('Role: ', JWT.GetClaim('role'));
      Writeln('Department: ', JWT.GetClaim('department'));
    end;
  finally
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(CustomClaims) then
      CustomClaims.Free;
  end;
end;
```

### HTTP Integration

```pascal
var
  JWT: TJWTToken;
begin
  JWT := nil;
  try
    // Extract token from Authorization header
    ExtractedToken := Manager.ExtractTokenFromAuthHeader('Bearer eyJhbGc...');

    // Validate with rate limiting
    if Manager.ValidateToken(ExtractedToken, JWT, ClientIP) then
      // Valid request
    else if JWT.LastError = jeRateLimited then
      // Too many attempts
  finally
    if Assigned(JWT) then
      JWT.Free;
  end;
end;
```

## Configuration

```pascal
Manager := TJWTManager.Create('key', 'issuer', 60);

// Set security parameters
Manager.ClockSkewTolerance := 30;        // 30 seconds tolerance
Manager.MaxTokenSize := 4096;            // 4KB maximum token size
Manager.MaxValidationAttempts := 5;      // 5 attempts per client
Manager.ValidationWindowMinutes := 15;   // 15-minute rate limit window
Manager.EnableSecurityLogging := True;   // Enable event logging
```

## Testing

Run the included examples:
- `GJWTExample01.exe` - Comprehensive security tests
- `GJWTExample02.exe` - Feature demonstrations



### Recommended Production Settings
```pascal
Manager.ClockSkewTolerance := 30;        // Handle 30-second time drift
Manager.MaxTokenSize := 4096;            // Prevent oversized tokens
Manager.MaxValidationAttempts := 5;      // Limit brute force attempts
Manager.ValidationWindowMinutes := 15;   // Reset rate limits every 15 minutes
Manager.EnableSecurityLogging := True;   // Log security events
```

## License

This project is licensed under the MIT License.
