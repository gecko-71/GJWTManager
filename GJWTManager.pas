unit GJWTManager;

interface

uses
  SysUtils, Classes, SyncObjs, System.Threading, System.StrUtils,
  System.JSON, System.NetEncoding, System.Generics.Collections,
  System.DateUtils, System.Hash, System.Math;

type
  TJWTError = (jeNone, jeInvalidFormat, jeInvalidSignature, jeExpiredToken,
               jeInvalidIssuer, jeInvalidAudience, jeNotYetValid, jeParsingError,
               jeEncodingError, jeInvalidHeader, jeInvalidPayload, jeTokenTooLarge,
               jeRateLimited, jeInvalidAlgorithm, jeInvalidTokenType, jeWeakKey,
               jeTokenFromFuture);

  TJWTToken = class
  private
    FHeader: string;
    FPayload: string;
    FSignature: string;
    FRaw: string;
    FDecoded: TJSONObject;
    FHeaderDecoded: TJSONObject;
    FExpirationTime: TDateTime;
    FIssuedAt: TDateTime;
    FNotBefore: TDateTime;
    FIsValid: Boolean;
    FSubject: string;
    FIssuer: string;
    FAudience: string;
    FJwtId: string;
    FLastError: TJWTError;
    FErrorMessage: string;
  public
    constructor Create;
    destructor Destroy; override;
    function GetClaim(const Name: string): string;
    procedure Clear;
    procedure SecureClear;
    property Header: string read FHeader write FHeader;
    property Payload: string read FPayload write FPayload;
    property Signature: string read FSignature write FSignature;
    property Raw: string read FRaw write FRaw;
    property Decoded: TJSONObject read FDecoded write FDecoded;
    property HeaderDecoded: TJSONObject read FHeaderDecoded write FHeaderDecoded;
    property ExpirationTime: TDateTime read FExpirationTime write FExpirationTime;
    property IssuedAt: TDateTime read FIssuedAt write FIssuedAt;
    property NotBefore: TDateTime read FNotBefore write FNotBefore;
    property IsValid: Boolean read FIsValid write FIsValid;
    property Subject: string read FSubject write FSubject;
    property Issuer: string read FIssuer write FIssuer;
    property Audience: string read FAudience write FAudience;
    property JwtId: string read FJwtId write FJwtId;
    property LastError: TJWTError read FLastError write FLastError;
    property ErrorMessage: string read FErrorMessage write FErrorMessage;
  end;

  TValidationAttempt = record
    LastAttempt: TDateTime;
    Count: Integer;
  end;

  TJWTManager = class
  private
    FSecretKey: string;
    FIssuer: string;
    FAudience: string;
    FTokenExpiration: Integer;
    FClockSkewTolerance: Integer;
    FMaxTokenSize: Integer;
    FAllowedAlgorithms: TArray<string>;
    FValidationAttempts: TDictionary<string, TValidationAttempt>;
    FValidationLock: TCriticalSection;
    FMaxValidationAttempts: Integer;
    FValidationWindowMinutes: Integer;
    FEnableSecurityLogging: Boolean;

    function ValidateAlgorithm(const Algorithm: string): Boolean;
    function CreateSignature(const HeaderPayload: string): string;
    function VerifySignature(const HeaderPayload, Signature: string): Boolean;
    function SecureCompare(const A, B: string): Boolean;
    function DecodeBase64Url(const Input: string): string;
    function EncodeBase64Url(const Input: string): string;
    function ParseJsonSafely(const JsonStr: string): TJSONObject;
    function ValidateStandardClaims(const PayloadObj: TJSONObject; out Error: TJWTError; out ErrorMsg: string): Boolean;
    function IsValidSecretKey(const Key: string): Boolean;
    function IsRateLimited(const ClientId: string): Boolean;
    procedure UpdateValidationAttempt(const ClientId: string);
    procedure LogSecurityEvent(const Event: string; const Details: string = '');
    function GenerateSecureJti: string;
    procedure SecureZeroMemory(var Str: string);
    function ValidateTokenSize(const Token: string): Boolean;
    function ValidateHeaderSafely(const HeaderObj: TJSONObject): Boolean;
  public
    constructor Create(const ASecretKey, AIssuer: string; ATokenExpiration: Integer = 60; const AAudience: string = '');
    destructor Destroy; override;
    function ValidateToken(const Token: string; out JWT: TJWTToken): Boolean; overload;
    function ValidateToken(const Token: string; out JWT: TJWTToken; const ClientId: string): Boolean; overload;
    function CreateToken(const Subject: string; const CustomClaims: TJSONObject = nil; const JwtId: string = ''): string;
    function ExtractTokenFromAuthHeader(const AuthHeader: string): string;
    function RefreshToken(const Token: string; out NewToken: string): Boolean; overload;
    function RefreshToken(const Token: string; out NewToken: string; const ClientId: string): Boolean; overload;
    procedure ClearValidationHistory;

    property SecretKey: string read FSecretKey write FSecretKey;
    property Issuer: string read FIssuer write FIssuer;
    property Audience: string read FAudience write FAudience;
    property TokenExpiration: Integer read FTokenExpiration write FTokenExpiration;
    property ClockSkewTolerance: Integer read FClockSkewTolerance write FClockSkewTolerance;
    property MaxTokenSize: Integer read FMaxTokenSize write FMaxTokenSize;
    property AllowedAlgorithms: TArray<string> read FAllowedAlgorithms write FAllowedAlgorithms;
    property MaxValidationAttempts: Integer read FMaxValidationAttempts write FMaxValidationAttempts;
    property ValidationWindowMinutes: Integer read FValidationWindowMinutes write FValidationWindowMinutes;
    property EnableSecurityLogging: Boolean read FEnableSecurityLogging write FEnableSecurityLogging;
  end;

implementation

{ TJWTToken }
constructor TJWTToken.Create;
begin
  inherited Create;
  FDecoded := nil;
  FHeaderDecoded := nil;
  FExpirationTime := 0;
  FIssuedAt := 0;
  FNotBefore := 0;
  FIsValid := False;
  FLastError := jeNone;
  FHeader := '';
  FPayload := '';
  FSignature := '';
  FRaw := '';
  FSubject := '';
  FIssuer := '';
  FAudience := '';
  FJwtId := '';
  FErrorMessage := '';
end;

destructor TJWTToken.Destroy;
begin
  SecureClear;
  inherited Destroy;
end;

function TJWTToken.GetClaim(const Name: string): string;
var
  Value: TJSONValue;
begin
  Result := '';
  try
    if Assigned(FDecoded) then
    begin
      Value := FDecoded.FindValue(Name);
      if Assigned(Value) then
        Result := Value.Value;
    end;
  except
    on E: Exception do
      Result := '';
  end;
end;

procedure TJWTToken.Clear;
begin
  try
    if Assigned(FDecoded) then
    begin
      FDecoded.Free;
      FDecoded := nil;
    end;
  except
  end;

  try
    if Assigned(FHeaderDecoded) then
    begin
      FHeaderDecoded.Free;
      FHeaderDecoded := nil;
    end;
  except
  end;

  FHeader := '';
  FPayload := '';
  FSignature := '';
  FRaw := '';
  FExpirationTime := 0;
  FIssuedAt := 0;
  FNotBefore := 0;
  FIsValid := False;
  FSubject := '';
  FIssuer := '';
  FAudience := '';
  FJwtId := '';
  FLastError := jeNone;
  FErrorMessage := '';
end;

procedure TJWTToken.SecureClear;
begin
  if FRaw <> '' then
  begin
    FillChar(FRaw[1], Length(FRaw) * SizeOf(Char), 0);
    FRaw := '';
  end;

  if FSignature <> '' then
  begin
    FillChar(FSignature[1], Length(FSignature) * SizeOf(Char), 0);
    FSignature := '';
  end;

  Clear;
end;

{ TJWTManager }
constructor TJWTManager.Create(const ASecretKey, AIssuer: string; ATokenExpiration: Integer; const AAudience: string);
begin
  inherited Create;
  try
    if not IsValidSecretKey(ASecretKey) then
      raise Exception.Create('Invalid secret key: must be at least 32 characters long and properly encoded');

    FSecretKey := ASecretKey;
    FIssuer := AIssuer;
    FAudience := AAudience;
    FTokenExpiration := ATokenExpiration;
    FClockSkewTolerance := 30;
    FMaxTokenSize := 8192;
    FMaxValidationAttempts := 10;
    FValidationWindowMinutes := 15;
    FEnableSecurityLogging := True;
    SetLength(FAllowedAlgorithms, 1);
    FAllowedAlgorithms[0] := 'HS256';
    FValidationAttempts := TDictionary<string, TValidationAttempt>.Create;
    FValidationLock := TCriticalSection.Create;
    LogSecurityEvent('JWT Manager initialized', Format('Issuer: %s', [AIssuer]));
  except
    on E: Exception do
      raise Exception.Create('Failed to initialize JWT Manager: ' + E.Message);
  end;
end;

destructor TJWTManager.Destroy;
begin
  try
    LogSecurityEvent('JWT Manager destroyed');
    SecureZeroMemory(FSecretKey);
    SetLength(FAllowedAlgorithms, 0);
    if Assigned(FValidationAttempts) then
      FValidationAttempts.Free;
    if Assigned(FValidationLock) then
      FValidationLock.Free;
  finally
    inherited Destroy;
  end;
end;

function TJWTManager.IsValidSecretKey(const Key: string): Boolean;
begin
  Result := False;
  if Length(Key) < 32 then
    Exit;
  if Trim(Key) = '' then
    Exit;
  var UniqueChars := 0;
  var CharSet: set of Char := [];
  for var C in Key do
  begin
    if not (C in CharSet) then
    begin
      Include(CharSet,  AnsiChar(C));
      Inc(UniqueChars);
    end;
  end;
  Result := UniqueChars >= 16;
end;

function TJWTManager.ValidateAlgorithm(const Algorithm: string): Boolean;
var
  AllowedAlg: string;
begin
  Result := False;
  try
    if SameText(Algorithm, 'none') then
    begin
      LogSecurityEvent('Blocked none algorithm attack', Algorithm);
      Exit;
    end;

    for AllowedAlg in FAllowedAlgorithms do
    begin
      if SameText(Algorithm, AllowedAlg) then
      begin
        Result := True;
        Break;
      end;
    end;
  except
    on E: Exception do
    begin
      LogSecurityEvent('Algorithm validation error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.SecureCompare(const A, B: string): Boolean;
var
  i, MaxLen, Diff: Integer;
begin
  MaxLen := Max(Length(A), Length(B));
  Diff := Length(A) xor Length(B);

  for i := 1 to MaxLen do
  begin
    if i <= Length(A) then
      if i <= Length(B) then
        Diff := Diff or (Ord(A[i]) xor Ord(B[i]))
      else
        Diff := Diff or Ord(A[i])
    else
      if i <= Length(B) then
        Diff := Diff or Ord(B[i]);
  end;

  Result := Diff = 0;
end;

function TJWTManager.DecodeBase64Url(const Input: string): string;
var
  DecodedBytes: TBytes;
begin
  Result := '';
  try
    try
      DecodedBytes := TNetEncoding.Base64Url.DecodeStringToBytes(Input);
      Result := TEncoding.UTF8.GetString(DecodedBytes);
    except
      on E: EEncodingError do
      begin
        Result := TEncoding.ANSI.GetString(DecodedBytes);
      end;
    end;
  except
    on E: Exception do
    begin
      LogSecurityEvent('Base64 decode error', E.Message);
      Result := '';
    end;
  end;
end;

function TJWTManager.EncodeBase64Url(const Input: string): string;
begin
  Result := '';
  try
    Result := TNetEncoding.Base64Url.Encode(Input);
  except
    on E: Exception do
    begin
      LogSecurityEvent('Base64 encode error', E.Message);
      Result := '';
    end;
  end;
end;

function TJWTManager.ParseJsonSafely(const JsonStr: string): TJSONObject;
begin
  Result := nil;
  try
    if Length(JsonStr) > 4096 then
    begin
      LogSecurityEvent('JSON too large', Format('Size: %d bytes', [Length(JsonStr)]));
      Exit;
    end;

    Result := TJSONObject.ParseJSONValue(JsonStr) as TJSONObject;
  except
    on E: Exception do
    begin
      LogSecurityEvent('JSON parsing error', E.Message);
      if Assigned(Result) then
      begin
        Result.Free;
        Result := nil;
      end;
    end;
  end;
end;

function TJWTManager.CreateSignature(const HeaderPayload: string): string;
var
  HashBytes: TBytes;
begin
  Result := '';
  try
    HashBytes := THashSHA2.GetHashBytes(HeaderPayload + FSecretKey, THashSHA2.TSHA2Version.SHA256);
    Result := TNetEncoding.Base64Url.EncodeBytesToString(HashBytes);
  except
    on E: Exception do
    begin
      LogSecurityEvent('Signature creation error', E.Message);
      Result := '';
    end;
  end;
end;

function TJWTManager.VerifySignature(const HeaderPayload, Signature: string): Boolean;
var
  ExpectedSignature: string;
begin
  Result := False;
  try
    ExpectedSignature := CreateSignature(HeaderPayload);
    Result := (ExpectedSignature <> '') and SecureCompare(ExpectedSignature, Signature);

    if not Result then
      LogSecurityEvent('Invalid signature detected');
  except
    on E: Exception do
    begin
      LogSecurityEvent('Signature verification error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.ValidateStandardClaims(const PayloadObj: TJSONObject; out Error: TJWTError; out ErrorMsg: string): Boolean;
var
  ExpClaim, IatClaim, NbfClaim, IssuerClaim, AudClaim: TJSONValue;
  ExpTime, IatTime, NbfTime: Int64;
  IssuerValue, AudValue: string;
  CurrentTime: TDateTime;
begin
  Result := False;
  Error := jeNone;
  ErrorMsg := '';
  CurrentTime := Now;
  try
    ExpClaim := PayloadObj.FindValue('exp');
    if Assigned(ExpClaim) and ExpClaim.TryGetValue<Int64>(ExpTime) then
    begin
      if CurrentTime > IncSecond(UnixToDateTime(ExpTime), FClockSkewTolerance) then
      begin
        Error := jeExpiredToken;
        ErrorMsg := 'Token has expired';
        LogSecurityEvent('Expired token', Format('Exp: %s, Now: %s', [DateTimeToStr(UnixToDateTime(ExpTime)), DateTimeToStr(CurrentTime)]));
        Exit;
      end;
    end;
    IatClaim := PayloadObj.FindValue('iat');
    if Assigned(IatClaim) and IatClaim.TryGetValue<Int64>(IatTime) then
    begin
      if UnixToDateTime(IatTime) > IncSecond(CurrentTime, FClockSkewTolerance) then
      begin
        Error := jeTokenFromFuture;
        ErrorMsg := 'Token issued in the future';
        LogSecurityEvent('Token from future', Format('Iat: %s, Now: %s', [DateTimeToStr(UnixToDateTime(IatTime)), DateTimeToStr(CurrentTime)]));
        Exit;
      end;
    end;

    NbfClaim := PayloadObj.FindValue('nbf');
    if Assigned(NbfClaim) and NbfClaim.TryGetValue<Int64>(NbfTime) then
    begin
      if CurrentTime < IncSecond(UnixToDateTime(NbfTime), -FClockSkewTolerance) then
      begin
        Error := jeNotYetValid;
        ErrorMsg := 'Token is not yet valid';
        LogSecurityEvent('Token not yet valid', Format('Nbf: %s, Now: %s', [DateTimeToStr(UnixToDateTime(NbfTime)), DateTimeToStr(CurrentTime)]));
        Exit;
      end;
    end;

    if FIssuer <> '' then
    begin
      IssuerClaim := PayloadObj.FindValue('iss');
      if Assigned(IssuerClaim) then
      begin
        IssuerValue := IssuerClaim.Value;
        if IssuerValue <> FIssuer then
        begin
          Error := jeInvalidIssuer;
          ErrorMsg := 'Invalid issuer';
          LogSecurityEvent('Invalid issuer', Format('Expected: %s, Got: %s', [FIssuer, IssuerValue]));
          Exit;
        end;
      end;
    end;
    if FAudience <> '' then
    begin
      AudClaim := PayloadObj.FindValue('aud');
      if Assigned(AudClaim) then
      begin
        AudValue := AudClaim.Value;
        if AudValue <> FAudience then
        begin
          Error := jeInvalidAudience;
          ErrorMsg := 'Invalid audience';
          LogSecurityEvent('Invalid audience', Format('Expected: %s, Got: %s', [FAudience, AudValue]));
          Exit;
        end;
      end;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      Error := jeParsingError;
      ErrorMsg := 'Error validating claims: ' + E.Message;
      LogSecurityEvent('Claims validation error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.ValidateTokenSize(const Token: string): Boolean;
begin
  Result := Length(Token) <= FMaxTokenSize;
  if not Result then
    LogSecurityEvent('Token too large', Format('Size: %d, Max: %d', [Length(Token), FMaxTokenSize]));
end;

function TJWTManager.ValidateHeaderSafely(const HeaderObj: TJSONObject): Boolean;
var
  AlgValue, TypValue: TJSONValue;
  Algorithm, TokenType: string;
begin
  Result := False;
  try
    AlgValue := HeaderObj.FindValue('alg');
    if not Assigned(AlgValue) then
    begin
      LogSecurityEvent('Missing algorithm in header');
      Exit;
    end;
    Algorithm := AlgValue.Value;
    if not ValidateAlgorithm(Algorithm) then
    begin
      LogSecurityEvent('Invalid algorithm', Algorithm);
      Exit;
    end;
    TypValue := HeaderObj.FindValue('typ');
    if Assigned(TypValue) then
    begin
      TokenType := TypValue.Value;
      if not SameText(TokenType, 'JWT') then
      begin
        LogSecurityEvent('Invalid token type', TokenType);
        Exit;
      end;
    end;

    Result := True;
  except
    on E: Exception do
    begin
      LogSecurityEvent('Header validation error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.IsRateLimited(const ClientId: string): Boolean;
var
  Attempt: TValidationAttempt;
  CurrentTime: TDateTime;
begin
  Result := False;
  if ClientId = '' then Exit;

  FValidationLock.Enter;
  try
    CurrentTime := Now;
    if FValidationAttempts.TryGetValue(ClientId, Attempt) then
    begin
      if MinutesBetween(CurrentTime, Attempt.LastAttempt) >= FValidationWindowMinutes then
      begin
        Attempt.Count := 0;
        Attempt.LastAttempt := CurrentTime;
        FValidationAttempts.AddOrSetValue(ClientId, Attempt);
      end
      else if Attempt.Count >= FMaxValidationAttempts then
      begin
        Result := True;
        LogSecurityEvent('Rate limit exceeded', Format('Client: %s, Attempts: %d', [ClientId, Attempt.Count]));
      end;
    end;
  finally
    FValidationLock.Leave;
  end;
end;

procedure TJWTManager.UpdateValidationAttempt(const ClientId: string);
var
  Attempt: TValidationAttempt;
  CurrentTime: TDateTime;
begin
  if ClientId = '' then Exit;

  FValidationLock.Enter;
  try
    CurrentTime := Now;
    if FValidationAttempts.TryGetValue(ClientId, Attempt) then
    begin
      if MinutesBetween(CurrentTime, Attempt.LastAttempt) >= FValidationWindowMinutes then
      begin
        Attempt.Count := 1;
      end
      else
      begin
        Inc(Attempt.Count);
      end;
    end
    else
    begin
      Attempt.Count := 1;
    end;
    Attempt.LastAttempt := CurrentTime;
    FValidationAttempts.AddOrSetValue(ClientId, Attempt);
  finally
    FValidationLock.Leave;
  end;
end;

procedure TJWTManager.LogSecurityEvent(const Event: string; const Details: string);
begin
  if not FEnableSecurityLogging then Exit;
  try
    var LogMsg := Format('[%s] JWT Security: %s', [DateTimeToStr(Now), Event]);
    if Details <> '' then
      LogMsg := LogMsg + ' - ' + Details;

    Writeln(LogMsg);
  except
  end;
end;

function TJWTManager.GenerateSecureJti: string;
begin
  Result := THashSHA2.GetHashString(
                        GUIDToString(TGUID.NewGuid) +
                        IntToStr(DateTimeToUnix(Now)) +
                        IntToStr(Random(MaxInt)),
                        THashSHA2.TSHA2Version.SHA256);
end;

procedure TJWTManager.SecureZeroMemory(var Str: string);
begin
  if Str <> '' then
  begin
    FillChar(Str[1], Length(Str) * SizeOf(Char), 0);
    Str := '';
  end;
end;

function TJWTManager.ExtractTokenFromAuthHeader(const AuthHeader: string): string;
begin
  Result := '';
  try
    if StartsText('Bearer ', AuthHeader) then
      Result := Trim(Copy(AuthHeader, 8, MaxInt));
  except
    on E: Exception do
    begin
      LogSecurityEvent('Auth header extraction error', E.Message);
      Result := '';
    end;
  end;
end;

function TJWTManager.ValidateToken(const Token: string; out JWT: TJWTToken): Boolean;
begin
  Result := ValidateToken(Token, JWT, '');
end;

function TJWTManager.ValidateToken(const Token: string; out JWT: TJWTToken; const ClientId: string): Boolean;
var
  TokenParts: TArray<string>;
  HeaderStr, PayloadStr, SignatureStr: string;
  HeaderObj, PayloadObj: TJSONObject;
  ExpClaim, IatClaim, NbfClaim, SubjectClaim, IssuerClaim, AudClaim, JtiClaim: TJSONValue;
  ExpTime, IatTime, NbfTime: Int64;
  Error: TJWTError;
  ErrorMsg: string;
begin
  Result := False;
  JWT := TJWTToken.Create;
  JWT.Raw := Token;
  HeaderObj := nil;
  PayloadObj := nil;
  try
    if IsRateLimited(ClientId) then
    begin
      JWT.LastError := jeRateLimited;
      JWT.ErrorMessage := 'Too many validation attempts';
      Exit;
    end;
    UpdateValidationAttempt(ClientId);
    if not ValidateTokenSize(Token) then
    begin
      JWT.LastError := jeTokenTooLarge;
      JWT.ErrorMessage := Format('Token too large (max %d bytes)', [FMaxTokenSize]);
      Exit;
    end;
    TokenParts := Token.Split(['.']);
    if Length(TokenParts) <> 3 then
    begin
      JWT.LastError := jeInvalidFormat;
      JWT.ErrorMessage := 'Token must have exactly 3 parts separated by dots';
      LogSecurityEvent('Invalid token format', Format('Parts: %d', [Length(TokenParts)]));
      Exit;
    end;
    HeaderStr := TokenParts[0];
    PayloadStr := TokenParts[1];
    SignatureStr := TokenParts[2];
    JWT.Header := HeaderStr;
    JWT.Payload := PayloadStr;
    JWT.Signature := SignatureStr;
    HeaderObj := ParseJsonSafely(DecodeBase64Url(HeaderStr));
    if not Assigned(HeaderObj) then
    begin
      JWT.LastError := jeInvalidHeader;
      JWT.ErrorMessage := 'Cannot decode token header';
      Exit;
    end;

    if not ValidateHeaderSafely(HeaderObj) then
    begin
      JWT.LastError := jeInvalidHeader;
      JWT.ErrorMessage := 'Invalid header content';
      HeaderObj.Free;
      Exit;
    end;
    if not VerifySignature(HeaderStr + '.' + PayloadStr, SignatureStr) then
    begin
      JWT.LastError := jeInvalidSignature;
      JWT.ErrorMessage := 'Invalid token signature';
      HeaderObj.Free;
      Exit;
    end;
    PayloadObj := ParseJsonSafely(DecodeBase64Url(PayloadStr));
    if not Assigned(PayloadObj) then
    begin
      JWT.LastError := jeInvalidPayload;
      JWT.ErrorMessage := 'Cannot decode token payload';
      HeaderObj.Free;
      Exit;
    end;
    if not ValidateStandardClaims(PayloadObj, Error, ErrorMsg) then
    begin
      JWT.LastError := Error;
      JWT.ErrorMessage := ErrorMsg;
      HeaderObj.Free;
      PayloadObj.Free;
      Exit;
    end;
    ExpClaim := PayloadObj.FindValue('exp');
    if Assigned(ExpClaim) and ExpClaim.TryGetValue<Int64>(ExpTime) then
      JWT.ExpirationTime := UnixToDateTime(ExpTime);

    IatClaim := PayloadObj.FindValue('iat');
    if Assigned(IatClaim) and IatClaim.TryGetValue<Int64>(IatTime) then
      JWT.IssuedAt := UnixToDateTime(IatTime);

    NbfClaim := PayloadObj.FindValue('nbf');
    if Assigned(NbfClaim) and NbfClaim.TryGetValue<Int64>(NbfTime) then
      JWT.NotBefore := UnixToDateTime(NbfTime);

    SubjectClaim := PayloadObj.FindValue('sub');
    if Assigned(SubjectClaim) then
      JWT.Subject := SubjectClaim.Value;

    IssuerClaim := PayloadObj.FindValue('iss');
    if Assigned(IssuerClaim) then
      JWT.Issuer := IssuerClaim.Value;

    AudClaim := PayloadObj.FindValue('aud');
    if Assigned(AudClaim) then
      JWT.Audience := AudClaim.Value;

    JtiClaim := PayloadObj.FindValue('jti');
    if Assigned(JtiClaim) then
      JWT.JwtId := JtiClaim.Value;

    JWT.HeaderDecoded := HeaderObj;
    JWT.Decoded := PayloadObj;
    JWT.IsValid := True;
    Result := True;

  except
    on E: Exception do
    begin
      JWT.LastError := jeParsingError;
      JWT.ErrorMessage := 'Unexpected error: ' + E.Message;
      LogSecurityEvent('Token validation error', E.Message);
      Result := False;
      if Assigned(HeaderObj) then
        HeaderObj.Free;
      if Assigned(PayloadObj) then
        PayloadObj.Free;
    end;
  end;
end;

function TJWTManager.CreateToken(const Subject: string; const CustomClaims: TJSONObject; const JwtId: string): string;
var
  Header, Payload: TJSONObject;
  HeaderBase64, PayloadBase64, Signature: string;
  CurrentTime: TDateTime;
  Pair: TJSONPair;
  GeneratedJti: string;
begin
  Result := '';
  Header := nil;
  Payload := nil;

  try
    try
      CurrentTime := Now;
      Header := TJSONObject.Create;
      Header.AddPair('alg', 'HS256');
      Header.AddPair('typ', 'JWT');
      Payload := TJSONObject.Create;
      Payload.AddPair('sub', Subject);
      if FIssuer <> '' then
        Payload.AddPair('iss', FIssuer);
      if FAudience <> '' then
        Payload.AddPair('aud', FAudience);
      Payload.AddPair('iat', TJSONNumber.Create(DateTimeToUnix(CurrentTime)));
      Payload.AddPair('exp', TJSONNumber.Create(DateTimeToUnix(IncMinute(CurrentTime, FTokenExpiration))));
      if JwtId <> '' then
        GeneratedJti := JwtId
      else
        GeneratedJti := GenerateSecureJti;
      Payload.AddPair('jti', GeneratedJti);
      if Assigned(CustomClaims) then
      begin
        for Pair in CustomClaims do
        begin
          if Assigned(Pair.JsonString) and Assigned(Pair.JsonValue) then
          begin
            var ClaimName := Pair.JsonString.Value;
            if not (SameText(ClaimName, 'sub') or SameText(ClaimName, 'iss') or
                    SameText(ClaimName, 'aud') or SameText(ClaimName, 'iat') or
                    SameText(ClaimName, 'exp') or SameText(ClaimName, 'nbf') or
                    SameText(ClaimName, 'jti')) then
              Payload.AddPair(ClaimName, Pair.JsonValue.Clone as TJSONValue);
          end;
        end;
      end;
      HeaderBase64 := EncodeBase64Url(Header.ToString);
      PayloadBase64 := EncodeBase64Url(Payload.ToString);
      if (HeaderBase64 = '') or (PayloadBase64 = '') then
      begin
        LogSecurityEvent('Token creation failed', 'Base64 encoding failed');
        Exit;
      end;
      Signature := CreateSignature(HeaderBase64 + '.' + PayloadBase64);
      if Signature = '' then
      begin
        LogSecurityEvent('Token creation failed', 'Signature creation failed');
        Exit;
      end;
      Result := HeaderBase64 + '.' + PayloadBase64 + '.' + Signature;
      LogSecurityEvent('Token created', Format('Subject: %s, JTI: %s', [Subject, GeneratedJti]));
    except
      on E: Exception do
      begin
        LogSecurityEvent('Token creation error', E.Message);
        Result := '';
      end;
    end;
  finally
    if Assigned(Header) then
    begin
      try
        Header.Free;
      except
      end;
    end;

    if Assigned(Payload) then
    begin
      try
        Payload.Free;
      except
      end;
    end;
  end;
end;

function TJWTManager.RefreshToken(const Token: string; out NewToken: string): Boolean;
begin
  Result := RefreshToken(Token, NewToken, '');
end;

function TJWTManager.RefreshToken(const Token: string; out NewToken: string; const ClientId: string): Boolean;
var
  JWT: TJWTToken;
  CustomClaims: TJSONObject;
  Pair: TJSONPair;
begin
  Result := False;
  NewToken := '';
  JWT := nil;
  CustomClaims := nil;
  try
    try
      if not ValidateToken(Token, JWT, ClientId) then
      begin
        LogSecurityEvent('Refresh failed - invalid token', JWT.ErrorMessage);
        Exit;
      end;
      CustomClaims := TJSONObject.Create;
      if Assigned(JWT.Decoded) then
      begin
        for Pair in JWT.Decoded do
        begin
          if Assigned(Pair.JsonString) and Assigned(Pair.JsonValue) then
          begin
            var ClaimName := Pair.JsonString.Value;
            if not (SameText(ClaimName, 'sub') or SameText(ClaimName, 'iss') or
                    SameText(ClaimName, 'aud') or SameText(ClaimName, 'iat') or
                    SameText(ClaimName, 'exp') or SameText(ClaimName, 'nbf') or
                    SameText(ClaimName, 'jti')) then
            begin
              CustomClaims.AddPair(ClaimName, Pair.JsonValue.Clone as TJSONValue);
            end;
          end;
        end;
      end;
      Sleep(1);
      NewToken := CreateToken(JWT.Subject, CustomClaims);
      Result := NewToken <> '';
      if Result then
        LogSecurityEvent('Token refreshed', Format('Subject: %s', [JWT.Subject]))
      else
        LogSecurityEvent('Token refresh failed', 'Could not create new token');
    except
      on E: Exception do
      begin
        LogSecurityEvent('Token refresh error', E.Message);
        Result := False;
      end;
    end;
  finally
    if Assigned(JWT) then
      JWT.Free;
    if Assigned(CustomClaims) then
      CustomClaims.Free;
  end;
end;

procedure TJWTManager.ClearValidationHistory;
begin
  FValidationLock.Enter;
  try
    FValidationAttempts.Clear;
    LogSecurityEvent('Validation history cleared');
  finally
    FValidationLock.Leave;
  end;
end;

end.
