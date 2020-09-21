package simple_jwt

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

//func TestUTC(t *testing.T) {
//	utcTime := time.Now().UTC()
//
//	unix := utcTime.Unix() / 60
//
//	utcTime2 := time.Unix(unix*60, 0).UTC()
//
//	t.Log(utcTime, " vs ", utcTime2)
//
//	assert.Equal(t, utcTime, utcTime2)
//}

func SameToTheMinute(t1 time.Time, t2 time.Time) bool {
	return t1.UTC().Unix()/30 == t2.UTC().Unix()/30
}

func TestMakeToken(t *testing.T) {
	expire := time.Date(2020, time.December, 1, 0, 0, 0, 0, time.UTC)
	issuedAt := time.Date(2020, time.July, 1, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	simple := NewSimpleClaim().SetID("123").SetIssuer("issuer").
		SetSubject("subject").SetTokenType("access").
		AddAudience("one").AddAudience("two").
		SetExpirationTime(expire).SetNotBefore(notBefore).SetIssuedAt(issuedAt)

	assert.Equal(t, "123", simple.GetID())
	assert.Equal(t, "issuer", simple.GetIssuer())
	assert.Equal(t, "subject", simple.GetSubject())
	assert.Equal(t, "access", simple.GetTokenType())
	assert.Equal(t, 2, len(simple.GetAudiences()))
	assert.Equal(t, "one", simple.GetAudiences()[0])
	assert.Equal(t, "two", simple.GetAudiences()[1])

	expireZone, expireOffset := expire.Zone()
	expZone, expOff := simple.GetExpirationTime().Zone()
	assert.Equal(t, expireZone, expZone)
	assert.Equal(t, expireOffset, expOff)

	assert.True(t, SameToTheMinute(expire, simple.GetExpirationTime()))
	assert.True(t, SameToTheMinute(issuedAt, simple.GetIssuedAt()))
	assert.True(t, SameToTheMinute(notBefore, simple.GetNotBefore()))

	token, err := MakeToken("thisistrullyasecret", simple)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
	t.Log(token)

	simple2, err := GetClaims(token)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}

	assert.Equal(t, "123", simple2.GetID())
	assert.Equal(t, "issuer", simple2.GetIssuer())
	assert.Equal(t, "subject", simple2.GetSubject())
	assert.Equal(t, "access", simple2.GetTokenType())
	assert.Equal(t, 2, len(simple2.GetAudiences()))
	assert.Equal(t, "one", simple2.GetAudiences()[0])
	assert.Equal(t, "two", simple2.GetAudiences()[1])

	fmt.Printf("%v vs %v\n", expire, simple2.GetExpirationTime())
	assert.True(t, SameToTheMinute(expire, simple2.GetExpirationTime()))
	assert.True(t, SameToTheMinute(issuedAt, simple2.GetIssuedAt()))
	assert.True(t, SameToTheMinute(notBefore, simple2.GetNotBefore()))
}

func TestTokenExpired(t *testing.T) {
	expire := time.Now().Add(-2 * time.Minute)
	issuedAt := time.Now().Add(-6 * time.Minute)
	notBefore := time.Now().Add(-4 * time.Minute)
	simple := NewSimpleClaim().SetID("123").SetIssuer("issuer").
		SetSubject("subject").SetTokenType("access").
		AddAudience("one").AddAudience("two").
		SetExpirationTime(expire).SetNotBefore(notBefore).SetIssuedAt(issuedAt)

	token, err := MakeToken("thisistrullyasecret", simple)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
	t.Log(token)

	err = GetValidityError("thisistrullyasecret", token)
	assert.Error(t, err)
	assert.Equal(t, TokenTooLateError, err)
}

func TestTokenNotBefore(t *testing.T) {
	expire := time.Now().Add(10 * time.Minute)
	issuedAt := time.Now().Add(-10 * time.Minute)
	notBefore := time.Now().Add(2 * time.Minute)
	simple := NewSimpleClaim().SetID("123").SetIssuer("issuer").
		SetSubject("subject").SetTokenType("access").
		AddAudience("one").AddAudience("two").
		SetExpirationTime(expire).SetNotBefore(notBefore).SetIssuedAt(issuedAt)

	token, err := MakeToken("thisistrullyasecret", simple)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
	t.Log(token)

	err = GetValidityError("thisistrullyasecret", token)
	assert.Error(t, err)
	assert.Equal(t, TokenTooEarlyError, err)
}

func TestTokenValid(t *testing.T) {
	expire := time.Now().Add(10 * time.Minute)
	issuedAt := time.Now().Add(-10 * time.Minute)
	notBefore := time.Now().Add(-2 * time.Minute)
	simple := NewSimpleClaim().SetID("123").SetIssuer("issuer").
		SetSubject("subject").SetTokenType("access").
		AddAudience("one").AddAudience("two").
		SetExpirationTime(expire).SetNotBefore(notBefore).SetIssuedAt(issuedAt)

	token, err := MakeToken("thisistrullyasecret", simple)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
	t.Log(token)

	err = GetValidityError("thisistrullyasecret", token)
	assert.Nil(t, err)
}
