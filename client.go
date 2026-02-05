package stimatasdkgo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL = "http://localhost:9091/api"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	BaseURL      string
	Scopes       []string
}

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

type Client struct {
	config     Config
	httpClient *http.Client
}

func New(cfg Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) AuthCodeURL() (string, string) {
	state := generateRandomState()

	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", c.config.ClientID)
	v.Set("redirect_uri", c.config.RedirectURI)
	v.Set("scope", strings.Join(c.config.Scopes, " "))
	v.Set("state", state)

	return fmt.Sprintf("%s/oauth/authorize?%s", c.config.BaseURL, v.Encode()), state
}

func (c *Client) HandleCallback(ctx context.Context, r *http.Request, expectedState string) (*Token, error) {
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	errStr := query.Get("error")

	if errStr != "" {
		desc := query.Get("error_description")
		return nil, fmt.Errorf("oauth error: %s - %s", errStr, desc)
	}

	if code == "" {
		return nil, errors.New("missing 'code' parameter in callback URL")
	}

	if state == "" || state != expectedState {
		return nil, errors.New("invalid state parameter (potential CSRF)")
	}

	return c.exchange(ctx, code)
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	return c.doTokenRequest(ctx, data)
}

func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectResponse, error) {
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/oauth/introspect", c.config.BaseURL), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("introspection failed: %s", string(body))
	}

	var result IntrospectResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) Revoke(ctx context.Context, token string) error {
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/oauth/revoke", c.config.BaseURL), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation failed with status: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) GetUser(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/auth/me", c.config.BaseURL), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch user failed: %s", string(body))
	}

	var apiResp struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   string          `json:"error"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	if !apiResp.Success {
		return nil, errors.New(apiResp.Error)
	}

	var user User
	if err := json.Unmarshal(apiResp.Data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (c *Client) SwitchRole(ctx context.Context, accessToken, role string) (*Token, error) {
	data := struct {
		Role string `json:"role"`
	}{
		Role: role,
	}

	bodyBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/oauth/switch-role", c.config.BaseURL), strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("switch role failed: %s", string(body))
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (c *Client) CheckAccess(ctx context.Context, accessToken, resource string) (bool, error) {
	v := url.Values{}
	v.Set("resource", resource)

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v1/check-access?%s", c.config.BaseURL, v.Encode()), nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("check access failed: %s", string(body))
	}

	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Allowed bool `json:"allowed"`
			User    User `json:"user"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Data.Allowed, nil
}

func (c *Client) exchange(ctx context.Context, code string) (*Token, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.config.RedirectURI)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	return c.doTokenRequest(ctx, data)
}

func (c *Client) doTokenRequest(ctx context.Context, data url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/oauth/token", c.config.BaseURL), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed: %s", string(body))
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func generateRandomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
