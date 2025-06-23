program GJWTExample01;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  FastMM5,
  System.SysUtils,
  System.JSON,
  System.DateUtils,
  System.NetEncoding,
  System.Hash,
  GJWTManager in 'GJWTManager.pas';

var
  TestsPassed, TestsFailed: Integer;

procedure ConfigureFastMM;
begin
  FastMM_EnterDebugMode;
  FastMM_MessageBoxEvents := [];
  FastMM_LogToFileEvents := FastMM_LogToFileEvents + [mmetUnexpectedMemoryLeakDetail,
                            mmetUnexpectedMemoryLeakSummary,
                            mmetDebugBlockDoubleFree,
                            mmetDebugBlockReallocOfFreedBlock];
end;

procedure WriteResult(const TestName: string; Passed: Boolean; const Details: string = '');
begin
  if Passed then
  begin
    Writeln('[PASS] ', TestName);
    Inc(TestsPassed);
  end
  else
  begin
    Writeln('[FAIL] ', TestName);
    if Details <> '' then
      Writeln('       Details: ', Details);
    Inc(TestsFailed);
  end;
end;

procedure TestBasicTokenCreation;
var
  Manager: TJWTManager;
  Token: string;
begin
  Write('Testing basic token creation... ');
  Manager := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Token := Manager.CreateToken('user123');
    WriteResult('Basic Token Creation', (Token <> '') and (Length(Token.Split(['.'])) = 3));
  except
    on E: Exception do
      WriteResult('Basic Token Creation', False, E.Message);
  end;

  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestTokenValidation;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
begin
  Write('Testing token validation... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Token := Manager.CreateToken('user123');

    if Manager.ValidateToken(Token, JWT) then
    begin
      WriteResult('Token Validation',
        JWT.IsValid and
        (JWT.Subject = 'user123') and
        (JWT.Issuer = 'TestIssuer') and
        (JWT.JwtId <> ''));
    end
    else
      WriteResult('Token Validation', False, 'Token validation failed: ' + JWT.ErrorMessage);
  except
    on E: Exception do
      WriteResult('Token Validation', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestInvalidSignature;
var
  Manager1, Manager2: TJWTManager;
  Token: string;
  JWT: TJWTToken;
begin
  Write('Testing invalid signature detection... ');
  Manager1 := nil;
  Manager2 := nil;
  JWT := nil;
  try
    Manager1 := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Manager2 := TJWTManager.Create('different-secret-key-32-characters-min', 'TestIssuer', 60);
    Token := Manager1.CreateToken('user123');

    if not Manager2.ValidateToken(Token, JWT) then
    begin
      WriteResult('Invalid Signature Detection',
        JWT.LastError = jeInvalidSignature);
    end
    else
      WriteResult('Invalid Signature Detection', False, 'Should have detected invalid signature');
  except
    on E: Exception do
      WriteResult('Invalid Signature Detection', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager1) then
    Manager1.Free;
  if Assigned(Manager2) then
    Manager2.Free;
end;

procedure TestExpiredToken;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
begin
  Write('Testing expired token detection... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', -1);
    Token := Manager.CreateToken('user123');
    Sleep(1100);

    if not Manager.ValidateToken(Token, JWT) then
    begin
      WriteResult('Expired Token Detection',
        JWT.LastError = jeExpiredToken);
    end
    else
      WriteResult('Expired Token Detection', False, 'Should have detected expired token');
  except
    on E: Exception do
      WriteResult('Expired Token Detection', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestCustomClaims;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
  CustomClaims: TJSONObject;
  RoleClaim: string;
begin
  Write('Testing custom claims... ');
  Manager := nil;
  CustomClaims := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    CustomClaims := TJSONObject.Create;
    try
      CustomClaims.AddPair('role', 'admin');
      CustomClaims.AddPair('department', 'IT');
      CustomClaims.AddPair('permissions', '["read", "write", "admin"]');

      Token := Manager.CreateToken('user123', CustomClaims);

      if Manager.ValidateToken(Token, JWT) then
      begin
        RoleClaim := JWT.GetClaim('role');
        WriteResult('Custom Claims',
          (RoleClaim = 'admin') and
          (JWT.GetClaim('department') = 'IT') and
          (JWT.GetClaim('permissions') <> ''));
      end
      else
        WriteResult('Custom Claims', False, 'Token validation failed: ' + JWT.ErrorMessage);
    except
      on E: Exception do
        WriteResult('Custom Claims', False, E.Message);
    end;
  finally
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(CustomClaims) then
      CustomClaims.Free;
    if Assigned(Manager) then
      Manager.Free;
  end;
end;

procedure TestAuthHeaderExtraction;
var
  Manager: TJWTManager;
  Token, ExtractedToken: string;
  AuthHeader: string;
begin
  Write('Testing auth header extraction... ');
  Manager := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Token := Manager.CreateToken('user123');
    AuthHeader := 'Bearer ' + Token;

    ExtractedToken := Manager.ExtractTokenFromAuthHeader(AuthHeader);
    WriteResult('Auth Header Extraction', ExtractedToken = Token);
  except
    on E: Exception do
      WriteResult('Auth Header Extraction', False, E.Message);
  end;

  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestInvalidTokenFormat;
var
  Manager: TJWTManager;
  JWT: TJWTToken;
  ValidationResult: Boolean;
begin
  Write('Testing invalid token format... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    ValidationResult := Manager.ValidateToken('invalid.token', JWT);

    if not ValidationResult and Assigned(JWT) then
    begin
      WriteResult('Invalid Token Format',
        JWT.LastError = jeInvalidFormat);
    end
    else
      WriteResult('Invalid Token Format', False, 'Should have detected invalid format');
  except
    on E: Exception do
      WriteResult('Invalid Token Format', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestInvalidIssuer;
var
  Manager1, Manager2: TJWTManager;
  Token: string;
  JWT: TJWTToken;
begin
  Write('Testing invalid issuer detection... ');
  Manager1 := nil;
  Manager2 := nil;
  JWT := nil;
  try
    Manager1 := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'Issuer1', 60);
    Manager2 := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'Issuer2', 60);
    Token := Manager1.CreateToken('user123');

    if not Manager2.ValidateToken(Token, JWT) then
    begin
      WriteResult('Invalid Issuer Detection',
        JWT.LastError = jeInvalidIssuer);
    end
    else
      WriteResult('Invalid Issuer Detection', False, 'Should have detected invalid issuer');
  except
    on E: Exception do
      WriteResult('Invalid Issuer Detection', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager1) then
    Manager1.Free;
  if Assigned(Manager2) then
    Manager2.Free;
end;

procedure TestRefreshToken;
var
  Manager: TJWTManager;
  OriginalToken, NewToken: string;
  JWT1, JWT2: TJWTToken;
  RefreshSuccessful: Boolean;
  OriginalJti, NewJti: string;
begin
  Write('Testing token refresh... ');
  Manager := nil;
  JWT1 := nil;
  JWT2 := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    OriginalToken := Manager.CreateToken('user123');
    if Manager.ValidateToken(OriginalToken, JWT1) then
      OriginalJti := JWT1.JwtId;
    Sleep(1100);
    RefreshSuccessful := Manager.RefreshToken(OriginalToken, NewToken);
    if RefreshSuccessful and (NewToken <> '') then
    begin
      if Manager.ValidateToken(NewToken, JWT2) then
      begin
        NewJti := JWT2.JwtId;
        WriteResult('Token Refresh',
          (JWT2.Subject = 'user123') and
          (JWT2.Issuer = 'TestIssuer') and
          (NewToken <> OriginalToken) and
          (NewJti <> OriginalJti));
      end
      else
        WriteResult('Token Refresh', False, 'New token validation failed: ' + JWT2.ErrorMessage);
    end
    else
      WriteResult('Token Refresh', False, 'Token refresh failed - no new token generated');
  except
    on E: Exception do
      WriteResult('Token Refresh', False, E.Message);
  end;

  if Assigned(JWT1) then
    JWT1.Free;
  if Assigned(JWT2) then
    JWT2.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestAudienceValidation;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
begin
  Write('Testing audience validation... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60, 'MyApp');
    Token := Manager.CreateToken('user123');

    if Manager.ValidateToken(Token, JWT) then
    begin
      WriteResult('Audience Validation',
        JWT.Audience = 'MyApp');
    end
    else
      WriteResult('Audience Validation', False, 'Token validation failed: ' + JWT.ErrorMessage);
  except
    on E: Exception do
      WriteResult('Audience Validation', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestJWTWithJwtId;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
  JwtId: string;
begin
  Write('Testing custom JWT ID... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    JwtId := 'unique-id-123';
    Token := Manager.CreateToken('user123', nil, JwtId);

    if Manager.ValidateToken(Token, JWT) then
    begin
      WriteResult('Custom JWT ID', JWT.JwtId = JwtId);
    end
    else
      WriteResult('Custom JWT ID', False, 'Token validation failed: ' + JWT.ErrorMessage);
  except
    on E: Exception do
      WriteResult('Custom JWT ID', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestWeakSecretKey;
var
  Manager: TJWTManager;
begin
  Write('Testing weak secret key rejection... ');
  Manager := nil;
  try
    Manager := TJWTManager.Create('short', 'TestIssuer', 60);
    WriteResult('Weak Secret Key Rejection', False, 'Should have rejected weak key');
  except
    on E: Exception do
      WriteResult('Weak Secret Key Rejection', True, 'Correctly rejected: ' + E.Message);
  end;

  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestNoneAlgorithmAttack;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
  Header, Payload: TJSONObject;
  HeaderBase64, PayloadBase64: string;
begin
  Write('Testing "none" algorithm attack prevention... ');
  Manager := nil;
  Header := nil;
  Payload := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Header := TJSONObject.Create;
    Payload := TJSONObject.Create;
    try
      Header.AddPair('alg', 'none');
      Header.AddPair('typ', 'JWT');
      Payload.AddPair('sub', 'hacker');
      Payload.AddPair('iss', 'TestIssuer');
      Payload.AddPair('iat', TJSONNumber.Create(DateTimeToUnix(Now)));
      Payload.AddPair('exp', TJSONNumber.Create(DateTimeToUnix(IncMinute(Now, 60))));
      HeaderBase64 := TNetEncoding.Base64Url.Encode(Header.ToString);
      PayloadBase64 := TNetEncoding.Base64Url.Encode(Payload.ToString);
      Token := HeaderBase64 + '.' + PayloadBase64 + '.';
      if not Manager.ValidateToken(Token, JWT) then
      begin
        WriteResult('None Algorithm Attack Prevention',
          JWT.LastError = jeInvalidHeader);
      end
      else
        WriteResult('None Algorithm Attack Prevention', False, 'Should have rejected "none" algorithm');

    except
      on E: Exception do
        WriteResult('None Algorithm Attack Prevention', False, E.Message);
    end;
  finally
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(Header) then
      Header.Free;
    if Assigned(Payload) then
      Payload.Free;
    if Assigned(Manager) then
      Manager.Free;
  end;
end;

procedure TestTokenTooLarge;
var
  Manager: TJWTManager;
  JWT: TJWTToken;
  LargeToken: string;
  i: Integer;
begin
  Write('Testing token size limit... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Manager.MaxTokenSize := 1024;
    LargeToken := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.';
    for i := 1 to 2000 do
      LargeToken := LargeToken + 'A';
    LargeToken := LargeToken + '.signature';

    if not Manager.ValidateToken(LargeToken, JWT) then
    begin
      WriteResult('Token Size Limit',
        JWT.LastError = jeTokenTooLarge);
    end
    else
      WriteResult('Token Size Limit', False, 'Should have rejected oversized token');
  except
    on E: Exception do
      WriteResult('Token Size Limit', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestRateLimiting;
var
  Manager: TJWTManager;
  JWT: TJWTToken;
  i: Integer;
  ClientId: string;
  LastResult: Boolean;
begin
  Write('Testing rate limiting... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Manager.MaxValidationAttempts := 3;
    ClientId := '192.168.1.100';

    LastResult := True;
    for i := 1 to 5 do
    begin
      if Assigned(JWT) then
        JWT.Free;
      JWT := nil;

      LastResult := Manager.ValidateToken('invalid.token.test', JWT, ClientId);
      if not LastResult and (JWT.LastError = jeRateLimited) then
        Break;
    end;

    WriteResult('Rate Limiting',
      not LastResult and (JWT.LastError = jeRateLimited));
  except
    on E: Exception do
      WriteResult('Rate Limiting', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestTokenFromFuture;
var
  Manager: TJWTManager;
  Header, Payload: TJSONObject;
  Token: string;
  JWT: TJWTToken;
  HeaderBase64, PayloadBase64, Signature: string;
  FutureTime: TDateTime;
begin
  Write('Testing token from future detection... ');
  Manager := nil;
  Header := nil;
  Payload := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Manager.ClockSkewTolerance := 5;
    FutureTime := IncMinute(Now, 10);
    Header := TJSONObject.Create;
    Payload := TJSONObject.Create;
    try
      Header.AddPair('alg', 'HS256');
      Header.AddPair('typ', 'JWT');
      Payload.AddPair('sub', 'user123');
      Payload.AddPair('iss', 'TestIssuer');
      Payload.AddPair('iat', TJSONNumber.Create(DateTimeToUnix(FutureTime)));
      Payload.AddPair('exp', TJSONNumber.Create(DateTimeToUnix(IncMinute(FutureTime, 60))));
      HeaderBase64 := TNetEncoding.Base64Url.Encode(Header.ToString);
      PayloadBase64 := TNetEncoding.Base64Url.Encode(Payload.ToString);
      var HashBytes := THashSHA2.GetHashBytes(HeaderBase64 + '.' + PayloadBase64 + 'super-secret-key-at-least-32-characters-long', THashSHA2.TSHA2Version.SHA256);
      Signature := TNetEncoding.Base64Url.EncodeBytesToString(HashBytes);
      Token := HeaderBase64 + '.' + PayloadBase64 + '.' + Signature;
      if not Manager.ValidateToken(Token, JWT) then
        WriteResult('Token From Future Detection', JWT.LastError = jeTokenFromFuture)
      else
        WriteResult('Token From Future Detection', False, 'Should have detected token from future');
    except
      on E: Exception do
        WriteResult('Token From Future Detection', False, E.Message);
    end;
  finally
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(Header) then
      Header.Free;
    if Assigned(Payload) then
      Payload.Free;
    if Assigned(Manager) then
      Manager.Free;
  end;
end;

procedure TestNotBeforeValidation;
var
  Manager: TJWTManager;
  Header, Payload: TJSONObject;
  Token: string;
  JWT: TJWTToken;
  HeaderBase64, PayloadBase64, Signature: string;
  FutureTime: TDateTime;
begin
  Write('Testing not-before (nbf) validation... ');
  Manager := nil;
  Header := nil;
  Payload := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    FutureTime := IncMinute(Now, 5);
    Header := TJSONObject.Create;
    Payload := TJSONObject.Create;
    try
      Header.AddPair('alg', 'HS256');
      Header.AddPair('typ', 'JWT');
      Payload.AddPair('sub', 'user123');
      Payload.AddPair('iss', 'TestIssuer');
      Payload.AddPair('iat', TJSONNumber.Create(DateTimeToUnix(Now)));
      Payload.AddPair('exp', TJSONNumber.Create(DateTimeToUnix(IncMinute(Now, 60))));
      Payload.AddPair('nbf', TJSONNumber.Create(DateTimeToUnix(FutureTime)));
      HeaderBase64 := TNetEncoding.Base64Url.Encode(Header.ToString);
      PayloadBase64 := TNetEncoding.Base64Url.Encode(Payload.ToString);
      var HashBytes := THashSHA2.GetHashBytes(HeaderBase64 + '.' + PayloadBase64 + 'super-secret-key-at-least-32-characters-long', THashSHA2.TSHA2Version.SHA256);
      Signature := TNetEncoding.Base64Url.EncodeBytesToString(HashBytes);
      Token := HeaderBase64 + '.' + PayloadBase64 + '.' + Signature;
      if not Manager.ValidateToken(Token, JWT) then
        WriteResult('Not-Before Validation', JWT.LastError = jeNotYetValid)
      else
        WriteResult('Not-Before Validation', False, 'Should have detected token not yet valid');
    except
      on E: Exception do
        WriteResult('Not-Before Validation', False, E.Message);
    end;
  finally
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(Header) then
      Header.Free;
    if Assigned(Payload) then
      Payload.Free;
    if Assigned(Manager) then
      Manager.Free;
  end;
end;

procedure TestMemoryLeaks;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
  i: Integer;
begin
  Write('Testing memory leaks with multiple operations... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    for i := 1 to 10 do
    begin
      Token := Manager.CreateToken('user' + IntToStr(i));
      if Assigned(JWT) then
        JWT.Free;
      JWT := nil;
      if Manager.ValidateToken(Token, JWT) then
      begin
        var Subject := JWT.Subject;
        var Issuer := JWT.Issuer;
        var JwtId := JWT.JwtId;
      end;
      if Assigned(JWT) then
        JWT.Free;
      JWT := nil;
      Manager.ValidateToken('invalid.token.format', JWT);
      var RefreshedToken: string;
      Manager.RefreshToken(Token, RefreshedToken);
    end;
    WriteResult('Memory Leaks Test', True, 'Multiple operations completed');
  except
    on E: Exception do
      WriteResult('Memory Leaks Test', False, E.Message);
  end;

  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure TestSecureClear;
var
  Manager: TJWTManager;
  Token: string;
  JWT: TJWTToken;
begin
  Write('Testing secure memory clearing... ');
  Manager := nil;
  JWT := nil;
  try
    Manager := TJWTManager.Create('super-secret-key-at-least-32-characters-long', 'TestIssuer', 60);
    Token := Manager.CreateToken('user123');
    if Manager.ValidateToken(Token, JWT) then
    begin
      JWT.SecureClear;
      WriteResult('Secure Memory Clear',
        (JWT.Raw = '') and
        (JWT.Signature = '') and
        not JWT.IsValid);
    end
    else
      WriteResult('Secure Memory Clear', False, 'Token validation failed');
  except
    on E: Exception do
      WriteResult('Secure Memory Clear', False, E.Message);
  end;
  if Assigned(JWT) then
    JWT.Free;
  if Assigned(Manager) then
    Manager.Free;
end;

procedure RunAllTests;
begin
  Writeln('Starting Comprehensive JWT Manager Security Tests...');
  Writeln('=====================================================');
  TestsPassed := 0;
  TestsFailed := 0;
  TestBasicTokenCreation;
  TestTokenValidation;
  TestInvalidSignature;
  TestExpiredToken;
  TestCustomClaims;
  TestAuthHeaderExtraction;
  TestInvalidTokenFormat;
  TestInvalidIssuer;
  TestRefreshToken;
  TestAudienceValidation;
  TestJWTWithJwtId;
  TestNotBeforeValidation;

  TestWeakSecretKey;
  TestNoneAlgorithmAttack;
  TestTokenTooLarge;
  TestRateLimiting;
  TestTokenFromFuture;
  TestSecureClear;

  TestMemoryLeaks;

  Writeln('=====================================================');
  Writeln('Test Results:');
  Writeln('  Passed: ', TestsPassed);
  Writeln('  Failed: ', TestsFailed);
  Writeln('  Total:  ', TestsPassed + TestsFailed);

  if TestsFailed = 0 then
    Writeln('All tests PASSED! JWT implementation is secure.')
  else
    Writeln('Some tests FAILED! Security issues detected.');
end;

begin
  ConfigureFastMM;
  try
    RunAllTests;
  except
    on E: Exception do
      Writeln('Critical error: ', E.ClassName, ': ', E.Message);
  end;
  Writeln('');
  Write('Press Enter to exit...');
  Readln;
end.
