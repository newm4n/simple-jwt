# simple-jwt

A very easy library for JWT. It uses [SermoDigital/jose](github.com/SermoDigital/jose) as foundation,
Really simple, no bullsh*t.

## Usage

```go
go get github.com/newm4n/simple-jwt
```

and 

```go
import (
    simplejwt "github.com/newm4n/simple-jwt"
)

```

### Create new Claim

```go
simple := simplejwt.NewSimpleClaim().SetID("123").SetIssuer("issuer").
    SetSubject("subject").SetTokenType("access").
    AddAudience("one").AddAudience("two")
```

or 

```go
simple := simplejwt.NewSimpleClaim()
simple.SetID("123")
simple.SetIssuer("issuer")
simple.SetSubject("subject")
simple.SetTokenType("access")
simple.AddAudience("one")
simple.AddAudience("two")
```

### Add expiry, not-before and issued-at

```go
expire := time.Now().Add(5 * time.Minute)
issuedAt := time.Now()
notBefore := time.Now()
simple := simplejwt.NewSimpleClaim().SetID("123").SetIssuer("issuer").
    SetSubject("subject").SetTokenType("access").
    AddAudience("one").AddAudience("two").
    SetExpirationTime(expire).SetNotBefore(notBefore).SetIssuedAt(issuedAt)
```

### Create a token

```go
simple := simplejwt.NewSimpleClaim()
token, err := simplejwt.MakeToken("this is a secret key", simple)
if err != nil {
    panic(err.Error())   
}
```

### Obtaining claims from a token

```go
token := "eyJhbGciOiJIUzI1NiIsInR5c...XlshT-jqnTKj20cogT707_gWKWTUxwXcsk"
simple, err := simplejwt.GetClaims(token)
```

### Validating a token

```go
token := "eyJhbGciOiJIUzI1NiIsInR5c...XlshT-jqnTKj20cogT707_gWKWTUxwXcsk"
err = simplejwt.GetValidityError("this is a secret key", token)
if err != nil {
    // token invalid signature, expired or not yet valid
}
```