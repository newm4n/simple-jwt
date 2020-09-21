package simple_jwt

import (
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"strings"
	"time"
)

var (
	// TokenTooLateError signify the error when the token is already expired.
	TokenTooLateError = fmt.Errorf("token has expired")

	// TokenTooEarlyError signify the error when the token is not yet valid for use.
	TokenTooEarlyError = fmt.Errorf("token has not enter its validity time")

	// SigningMethod is a method for encrypting the token.
	// You can use either :
	// crypto.SigningMethodHS256
	// crypto.SigningMethodHS384
	// crypto.SigningMethodHS512
	SigningMethod = crypto.SigningMethodHS256
)

// NewSimpleClaim create new simple claim object with default
// expiration, notbefore and issuedat claim value.
func NewSimpleClaim() *SimpleClaim {
	return &SimpleClaim{
		// default 10 years ahead, practically never expire
		expiration: time.Now().Add(24 * 360 * 10 * time.Hour),

		// default unix timestamp 0, practically already valid since 1970
		notBefore: time.Unix(0, 0),

		// default is now, the creation of this claim.
		issuedAt: time.Now(),
	}
}

// SimpleClaim simple claim host a claim structure
type SimpleClaim struct {
	content    map[string]interface{}
	expiration time.Time
	notBefore  time.Time
	issuedAt   time.Time
}

// SetID set the JWT ID
func (c *SimpleClaim) SetID(id string) *SimpleClaim {
	if c.content == nil {
		c.content = make(map[string]interface{})
	}
	c.content["jti"] = id
	return c
}

// GetID get the JWT ID
func (c *SimpleClaim) GetID() string {
	if c.content != nil {
		if iv, ok := c.content["jti"]; ok {
			return iv.(string)
		}
	}
	return ""
}

// SetIssuer set the ISSUER name
func (c *SimpleClaim) SetIssuer(issuer string) *SimpleClaim {
	if c.content == nil {
		c.content = make(map[string]interface{})
	}
	c.content["iss"] = issuer
	return c
}

// GetIssuer get the ISSUER name
func (c *SimpleClaim) GetIssuer() string {
	if c.content != nil {
		if iv, ok := c.content["iss"]; ok {
			return iv.(string)
		}
	}
	return ""
}

// SetSubject set the SUBJECT value
func (c *SimpleClaim) SetSubject(subject string) *SimpleClaim {
	if c.content == nil {
		c.content = make(map[string]interface{})
	}
	c.content["sub"] = subject
	return c
}

// GetSubject get the SUBJECT value
func (c *SimpleClaim) GetSubject() string {
	if c.content != nil {
		if iv, ok := c.content["sub"]; ok {
			return iv.(string)
		}
	}
	return ""
}

// AddAudience add audience into AUD values
func (c *SimpleClaim) AddAudience(audience string) *SimpleClaim {
	if c.content == nil {
		c.content = make(map[string]interface{})
	}
	if _, ok := c.content["aud"]; !ok {
		c.content["aud"] = make([]interface{}, 0)
	}
	audArray := c.content["aud"].([]interface{})
	audArray = append(audArray, audience)
	c.content["aud"] = audArray
	return c
}

// GetAudiences get all audiences in the AUD values
func (c *SimpleClaim) GetAudiences() []string {
	if c.content != nil {
		if audarritv, ok := c.content["aud"]; ok {
			audarr := audarritv.([]interface{})
			ret := make([]string, len(audarr))
			for i, audi := range audarr {
				ret[i] = audi.(string)
			}
			return ret
		}
	}
	return []string{}
}

// SetExpirationTime sets the token expiry time.
func (c *SimpleClaim) SetExpirationTime(t time.Time) *SimpleClaim {
	c.expiration = t
	return c
}

// GetExpirationTime get the token expiry time.
func (c *SimpleClaim) GetExpirationTime() time.Time {
	return c.expiration
}

// SetNotBefore set the start validity time
func (c *SimpleClaim) SetNotBefore(t time.Time) *SimpleClaim {
	c.notBefore = t
	return c
}

// GetNotBefore get the start validity time
func (c *SimpleClaim) GetNotBefore() time.Time {
	return c.notBefore
}

// SetIssuedAt set the token issue time
func (c *SimpleClaim) SetIssuedAt(t time.Time) *SimpleClaim {
	c.issuedAt = t
	return c
}

// GetIssuedAt get the token issue time
func (c *SimpleClaim) GetIssuedAt() time.Time {
	return c.issuedAt
}

// SetTokenType set the token type for simplicity reason or usage of Access/Refresh token
func (c *SimpleClaim) SetTokenType(tokenType string) *SimpleClaim {
	if c.content == nil {
		c.content = make(map[string]interface{})
	}
	c.content["typ"] = tokenType
	return c
}

// GetTokenType get the token type for simplicity reason or usage of Access/Refresh token
func (c *SimpleClaim) GetTokenType() string {
	if c.content != nil {
		if iv, ok := c.content["typ"]; ok {
			return iv.(string)
		}
	}
	return ""
}

// AddClaim add key value pair information into the claim in addition to the defaults
func (c *SimpleClaim) AddClaim(key string, value interface{}) *SimpleClaim {
	if c.content == nil {
		c.content = make(map[string]interface{})
	}
	lowKey := strings.TrimSpace(strings.ToLower(key))
	if lowKey == "iss" || lowKey == "sub" || lowKey == "aud" || lowKey == "exp" || lowKey == "nbf" || lowKey == "iat" || lowKey == "jti" || lowKey == "typ" {
		return c
	}
	c.content[key] = value
	return c
}

// GetClaim get claim value by its key
func (c *SimpleClaim) GetClaim(key string) interface{} {
	switch strings.TrimSpace(strings.ToLower(key)) {
	case "iss":
		return c.GetIssuer()
	case "sub":
		return c.GetSubject()
	case "aud":
		return c.GetAudiences()
	case "exp":
		return c.GetExpirationTime()
	case "nbf":
		return c.GetNotBefore()
	case "iat":
		return c.GetIssuedAt()
	case "jti":
		return c.GetID()
	case "typ":
		return c.GetTokenType()
	default:
		return c.content[key]
	}
}

// MakeToken create new token string of a simple claim
func MakeToken(secret string, simpleClaims *SimpleClaim) (string, error) {
	claims := jws.Claims{}
	for k, v := range simpleClaims.content {
		claims[k] = v
	}
	claims.SetExpiration(simpleClaims.expiration)
	claims.SetNotBefore(simpleClaims.notBefore)
	claims.SetIssuedAt(simpleClaims.issuedAt)
	jwtBytes := jws.NewJWT(claims, SigningMethod)
	tokenByte, err := jwtBytes.Serialize([]byte(secret))
	return string(tokenByte), err
}

// GetClaims extract a claim information from a token
func GetClaims(token string) (*SimpleClaim, error) {
	jwt, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return nil, err
	}
	claims := jwt.Claims()
	simple := &SimpleClaim{content: make(map[string]interface{})}
	for k, v := range claims {
		simple.content[k] = v
	}
	if exp, set := claims.Expiration(); set {
		simple.expiration = exp
	}
	if nbf, set := claims.NotBefore(); set {
		simple.notBefore = nbf
	}
	if iat, set := claims.IssuedAt(); set {
		simple.issuedAt = iat
	}
	return simple, nil
}

// GetValidityError will check token validity. If its valid, then there will be no error.
func GetValidityError(secret, token string) error {
	jwt, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return err
	}
	err = jwt.Validate([]byte(secret), SigningMethod)
	if err != nil {
		if err.Error() == "token is expired" {
			return TokenTooLateError
		}
		if err.Error() == "token is not yet valid" {
			return TokenTooEarlyError
		}
	}
	return err
}
