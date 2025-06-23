program GJWTExample02;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  FastMM5,
  System.SysUtils,
  System.JSON,
  GJWTManager in 'GJWTManager.pas';

var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
  CustomClaims: TJSONObject;

procedure ConfigureFastMM;
begin
  FastMM_EnterDebugMode;
  FastMM_MessageBoxEvents := [];
  FastMM_LogToFileEvents := FastMM_LogToFileEvents + [mmetUnexpectedMemoryLeakDetail,
                            mmetUnexpectedMemoryLeakSummary,
                            mmetDebugBlockDoubleFree,
                            mmetDebugBlockReallocOfFreedBlock];
end;

procedure PrintSeparator(const Title: string);
begin
  Writeln;
  Writeln('=== ', Title, ' ===');
  Writeln;
end;

procedure PrintTokenInfo(const JWT: TJWTToken);
begin
  Writeln('   Subject: ', JWT.Subject);
  Writeln('   Issuer: ', JWT.Issuer);
  if JWT.Audience <> '' then
    Writeln('   Audience: ', JWT.Audience);
  Writeln('   JWT ID: ', JWT.JwtId);
  Writeln('   Issued At: ', DateTimeToStr(JWT.IssuedAt));
  Writeln('   Expires: ', DateTimeToStr(JWT.ExpirationTime));
  if JWT.NotBefore > 0 then
    Writeln('   Not Before: ', DateTimeToStr(JWT.NotBefore));
end;

procedure DemonstrateBasicUsage;
begin
  PrintSeparator('Basic JWT Usage');
  Manager := TJWTManager.Create(
    'this-is-a-very-secure-secret-key-at-least-32-characters-long-for-production-use',
    'MySecureApplication',
    30,
    'api.myapp.com'
  );
  Manager.ClockSkewTolerance := 30;
  Manager.MaxTokenSize := 4096;
  Manager.MaxValidationAttempts := 5;
  Manager.ValidationWindowMinutes := 15;
  Writeln('JWT Manager created with secure configuration');
  Writeln('   Issuer: ', Manager.Issuer);
  Writeln('   Audience: ', Manager.Audience);
  Writeln('   Token Expiration: ', Manager.TokenExpiration, ' minutes');
  Writeln('   Max Token Size: ', Manager.MaxTokenSize, ' bytes');
  Writeln('   Rate Limit: ', Manager.MaxValidationAttempts, ' attempts per ', Manager.ValidationWindowMinutes, ' minutes');
end;

procedure DemonstrateTokenCreation;
begin
  PrintSeparator('Token Creation');
  Token := Manager.CreateToken('john.doe');
  Writeln('Simple token created');
  Writeln('   Token: ', Copy(Token, 1, 50), '...');
  Writeln('   Length: ', Length(Token), ' characters');
  Writeln('   Parts: ', Length(Token.Split(['.'])));
end;

procedure DemonstrateTokenValidation;
begin
  PrintSeparator('Token Validation');
  if Manager.ValidateToken(Token, JWT) then
  begin
    Writeln('Token is VALID!');
    PrintTokenInfo(JWT);
  end
  else
  begin
    Writeln('Token validation failed: ', JWT.ErrorMessage);
    Writeln('   Error code: ', Ord(JWT.LastError));
  end;
end;

procedure DemonstrateCustomClaims;
begin
  PrintSeparator('Custom Claims');
  if Assigned(JWT) then
    JWT.Free;
  JWT := nil;
  CustomClaims := TJSONObject.Create;
  try
    CustomClaims.AddPair('role', 'admin');
    CustomClaims.AddPair('department', 'IT');
    CustomClaims.AddPair('permissions', '["read", "write", "admin"]');
    CustomClaims.AddPair('session_id', 'sess_' + IntToStr(Random(999999)));
    Token := Manager.CreateToken('jane.smith', CustomClaims);
    Writeln('Token with custom claims created');
    if Manager.ValidateToken(Token, JWT) then
    begin
      Writeln('Token with custom claims validated');
      PrintTokenInfo(JWT);
      Writeln('   Custom Claims:');
      Writeln('     Role: ', JWT.GetClaim('role'));
      Writeln('     Department: ', JWT.GetClaim('department'));
      Writeln('     Permissions: ', JWT.GetClaim('permissions'));
      Writeln('     Session ID: ', JWT.GetClaim('session_id'));
    end
    else
    begin
      Writeln('Custom claims token validation failed: ', JWT.ErrorMessage);
    end;
  finally
    if Assigned(CustomClaims) then
      CustomClaims.Free;
  end;
end;

procedure DemonstrateSecurityFeatures;
begin
  PrintSeparator('Security Features Demo');
  if Assigned(JWT) then
    JWT.Free;
  JWT := nil;
  Writeln('Testing invalid token rejection...');
  if not Manager.ValidateToken('invalid.token.abc', JWT) then
  begin
    Writeln('Invalid token correctly rejected');
    Writeln('   Error: ', JWT.ErrorMessage);
    Writeln('   Error Type: ', Ord(JWT.LastError));
  end
  else
  begin
    Writeln('Security issue: Invalid token was accepted!');
  end;
  Writeln;
  Writeln('Testing rate limiting...');
  var ClientIP := '192.168.1.100';
  var AttemptCount := 0;
  for var i := 1 to 8 do
  begin
    if Assigned(JWT) then
      JWT.Free;
    JWT := nil;

    Inc(AttemptCount);
    var Success := Manager.ValidateToken('bad.token.test', JWT, ClientIP);

    if not Success and (JWT.LastError = jeRateLimited) then
    begin
      Writeln('Rate limiting activated after ', AttemptCount, ' attempts');
      Break;
    end;
  end;
  Manager.ClearValidationHistory;
end;

procedure DemonstrateAuthHeader;
begin
  PrintSeparator('HTTP Authorization Header');
  var ValidToken := Manager.CreateToken('api.user');
  var AuthHeader := 'Bearer ' + ValidToken;
  var ExtractedToken := Manager.ExtractTokenFromAuthHeader(AuthHeader);

  Writeln('Token extracted from HTTP header');
  Writeln('   Original Header: ', Copy(AuthHeader, 1, 40), '...');
  Writeln('   Extracted Token: ', Copy(ExtractedToken, 1, 40), '...');
  Writeln('   Tokens Match: ', ExtractedToken = ValidToken);

  if Assigned(JWT) then
    JWT.Free;
  JWT := nil;

  if Manager.ValidateToken(ExtractedToken, JWT) then
  begin
    Writeln('Extracted token is valid');
    Writeln('   Subject: ', JWT.Subject);
  end;
end;

procedure DemonstrateTokenRefresh;
begin
  PrintSeparator('Token Refresh');
  var OriginalToken := Manager.CreateToken('refresh.user');
  var RefreshedToken: string;
  Writeln('Original token created...');
  if Assigned(JWT) then
    JWT.Free;
  JWT := nil;
  Manager.ValidateToken(OriginalToken, JWT);
  var OriginalJti := JWT.JwtId;
  var OriginalIat := JWT.IssuedAt;

  Writeln('   Original JTI: ', Copy(OriginalJti, 1, 16), '...');
  Writeln('   Original IAT: ', DateTimeToStr(OriginalIat));
  Sleep(1100);
  if Manager.RefreshToken(OriginalToken, RefreshedToken) then
  begin
    Writeln('✅ Token successfully refreshed');
    if Assigned(JWT) then
      JWT.Free;
    JWT := nil;
    if Manager.ValidateToken(RefreshedToken, JWT) then
    begin
      Writeln('   New JTI: ', Copy(JWT.JwtId, 1, 16), '...');
      Writeln('   New IAT: ', DateTimeToStr(JWT.IssuedAt));
      Writeln('   Same Subject: ', JWT.Subject = 'refresh.user');
      Writeln('   Different JTI: ', JWT.JwtId <> OriginalJti);
      Writeln('   Newer IAT: ', JWT.IssuedAt > OriginalIat);
    end;
  end
  else
  begin
    Writeln('Token refresh failed');
  end;
end;

procedure DemonstrateAdvancedFeatures;
begin
  PrintSeparator('Advanced Features');
  var CustomJti := 'custom-jwt-id-' + IntToStr(Random(99999));
  var TokenWithCustomJti := Manager.CreateToken('advanced.user', nil, CustomJti);
  if Assigned(JWT) then
    JWT.Free;
  JWT := nil;
  if Manager.ValidateToken(TokenWithCustomJti, JWT) then
  begin
    Writeln('Token with custom JTI validated');
    Writeln('   Custom JTI: ', JWT.JwtId);
    Writeln('   Matches Expected: ', JWT.JwtId = CustomJti);
  end;
  Writeln;
  Writeln('Demonstrating secure memory clearing...');
  Writeln('   Before clear - Token length: ', Length(JWT.Raw));
  Writeln('   Before clear - Has signature: ', JWT.Signature <> '');
  JWT.SecureClear;
  Writeln('   After clear - Token length: ', Length(JWT.Raw));
  Writeln('   After clear - Has signature: ', JWT.Signature <> '');
  Writeln('   After clear - Is valid: ', JWT.IsValid);
  Writeln('Sensitive data securely cleared from memory');
end;

procedure DemonstrateErrorHandling;
begin
  PrintSeparator('Error Handling Examples');
  var TestCases: array[0..3] of record
    Description: string;
    Token: string;
    ExpectedError: TJWTError;
  end;
  TestCases[0].Description := 'Malformed token (wrong number of parts)';
  TestCases[0].Token := 'invalid.token';
  TestCases[0].ExpectedError := jeInvalidFormat;
  TestCases[1].Description := 'Empty token';
  TestCases[1].Token := '';
  TestCases[1].ExpectedError := jeInvalidFormat;
  TestCases[2].Description := 'Token with invalid base64';
  TestCases[2].Token := 'invalid-base64!@#.invalid-base64!@#.invalid-base64!@#';
  TestCases[2].ExpectedError := jeInvalidHeader;
  TestCases[3].Description := 'Well-formed but invalid signature';
  TestCases[3].Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaXNzIjoidGVzdCJ9.invalid_signature';
  TestCases[3].ExpectedError := jeInvalidSignature;
  for var TestCase in TestCases do
  begin
    if Assigned(JWT) then
      JWT.Free;
    JWT := nil;
    Writeln('Testing: ', TestCase.Description);
    if not Manager.ValidateToken(TestCase.Token, JWT) then
    begin
      Writeln('   Correctly rejected');
      Writeln('   Expected Error: ', Ord(TestCase.ExpectedError));
      Writeln('   Actual Error: ', Ord(JWT.LastError));
      Writeln('   Error Message: ', JWT.ErrorMessage);

      if JWT.LastError = TestCase.ExpectedError then
        Writeln('   Error type matches expectation')
      else
        Writeln('   Different error type than expected');
    end
    else
    begin
      Writeln('   Security issue: Invalid token was accepted!');
    end;
    Writeln;
  end;
end;

begin
  ConfigureFastMM;
  Manager := nil;
  JWT := nil;
  CustomClaims := nil;
  try
    Writeln('JWT Manager Enhanced Example with Security Features');
    Writeln('================================================');
    Randomize;
    DemonstrateBasicUsage;
    DemonstrateTokenCreation;
    DemonstrateTokenValidation;
    DemonstrateCustomClaims;
    DemonstrateSecurityFeatures;
    DemonstrateAuthHeader;
    DemonstrateTokenRefresh;
    DemonstrateAdvancedFeatures;
    DemonstrateErrorHandling;
    PrintSeparator('Summary');
    Writeln('All demonstrations completed successfully!');
    Writeln('');
    Writeln('Key Security Features Demonstrated:');
    Writeln('- Secure secret key validation');
    Writeln('- Rate limiting protection');
    Writeln('- Invalid token rejection');
    Writeln('- Secure memory clearing');
    Writeln('- Comprehensive error handling');
    Writeln('- JWT ID generation and validation');
    Writeln('- Token refresh functionality');
    Writeln('- HTTP header token extraction');
  except
    on E: Exception do
    begin
      Writeln('ERROR: ', E.Message);
      Writeln('Exception class: ', E.ClassName);
    end;
  end;
  try
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(Manager) then
      Manager.Free;
  except
  end;
  Writeln;
  Writeln('Press Enter to exit...');
  Readln;
end.
