# Stimata SDK for Go

A Go client library for integrating with the Stimata OAuth 2.0 authentication and authorization platform. This SDK provides a simple and secure way to implement OAuth 2.0 Authorization Code flow, token management, user information retrieval, role switching, and access control.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Features](#features)
  - [OAuth 2.0 Authorization Code Flow](#oauth-20-authorization-code-flow)
  - [Handle OAuth Callback](#handle-oauth-callback)
  - [Refresh Token](#refresh-token)
  - [Token Introspection](#token-introspection)
  - [Token Revocation](#token-revocation)
  - [Get User Information](#get-user-information)
  - [Switch Role](#switch-role)
  - [Check Access to Resource](#check-access-to-resource)
- [Data Types](#data-types)
- [Error Handling](#error-handling)
- [Complete Example](#complete-example)
- [Security Best Practices](#security-best-practices)
- [License](#license)

## Installation

```bash
go get github.com/stimata-team-dev/stimata-sdk-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"

    stimata "github.com/stimata-team-dev/stimata-sdk-go"
)

func main() {
    // Initialize the client
    client := stimata.New(stimata.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURI:  "http://localhost:8080/callback",
        BaseURL:      "https://auth.stimata.com/api",
        Scopes:       []string{"openid", "profile", "email"},
    })

    // Generate authorization URL
    authURL, state := client.AuthCodeURL()
    fmt.Printf("Visit this URL to authorize: %s\n", authURL)

    // Store `state` in session for CSRF verification
    // Redirect user to authURL...
}
```

## Configuration

Create a new client instance using the `New` function with a `Config` struct:

```go
client := stimata.New(stimata.Config{
    ClientID:     "your-client-id",      // Required: OAuth client ID
    ClientSecret: "your-client-secret",  // Required: OAuth client secret
    RedirectURI:  "http://localhost:8080/callback", // Required: Redirect URI after authorization
    BaseURL:      "https://auth.stimata.com/api",   // Optional: API base URL (default: http://localhost:9091/api)
    Scopes:       []string{"openid", "profile", "email"}, // Optional: OAuth scopes (default: openid, profile, email)
})
```

### Configuration Options

| Field          | Type       | Required | Default                          | Description                                  |
|----------------|------------|----------|----------------------------------|----------------------------------------------|
| `ClientID`     | `string`   | Yes      | -                                | Your OAuth 2.0 client identifier             |
| `ClientSecret` | `string`   | Yes      | -                                | Your OAuth 2.0 client secret                 |
| `RedirectURI`  | `string`   | Yes      | -                                | The callback URL after authorization         |
| `BaseURL`      | `string`   | No       | `http://localhost:9091/api`      | Stimata API base URL                         |
| `Scopes`       | `[]string` | No       | `["openid", "profile", "email"]` | OAuth scopes to request                      |

## Features

### OAuth 2.0 Authorization Code Flow

Generate an authorization URL to redirect users for authentication:

```go
authURL, state := client.AuthCodeURL()

// Store the state in user's session for CSRF protection
session.Values["oauth_state"] = state
session.Save(r, w)

// Redirect user to authorization URL
http.Redirect(w, r, authURL, http.StatusFound)
```

The `AuthCodeURL` method returns:
- `authURL`: The full authorization URL to redirect the user
- `state`: A randomly generated state parameter for CSRF protection

### Handle OAuth Callback

After the user authorizes your application, handle the callback to exchange the authorization code for tokens:

```go
func callbackHandler(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()
    
    // Retrieve the expected state from session
    expectedState := session.Values["oauth_state"].(string)
    
    // Handle the callback and exchange code for tokens
    token, err := client.HandleCallback(ctx, r, expectedState)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // Use the tokens
    fmt.Printf("Access Token: %s\n", token.AccessToken)
    fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
    fmt.Printf("Expires In: %d seconds\n", token.ExpiresIn)
}
```

### Refresh Token

Obtain a new access token using a refresh token:

```go
ctx := context.Background()

newToken, err := client.RefreshToken(ctx, "your-refresh-token")
if err != nil {
    log.Fatalf("Failed to refresh token: %v", err)
}

fmt.Printf("New Access Token: %s\n", newToken.AccessToken)
```

### Token Introspection

Validate and retrieve information about an access token:

```go
ctx := context.Background()

introspection, err := client.Introspect(ctx, "access-token-to-validate")
if err != nil {
    log.Fatalf("Failed to introspect token: %v", err)
}

if introspection.Active {
    fmt.Printf("Token is valid\n")
    fmt.Printf("Subject: %s\n", introspection.Sub)
    fmt.Printf("Scopes: %s\n", introspection.Scope)
    fmt.Printf("Expires: %d\n", introspection.Exp)
} else {
    fmt.Printf("Token is invalid or expired\n")
}
```

### Token Revocation

Revoke an access token or refresh token:

```go
ctx := context.Background()

err := client.Revoke(ctx, "token-to-revoke")
if err != nil {
    log.Fatalf("Failed to revoke token: %v", err)
}

fmt.Println("Token revoked successfully")
```

### Get User Information

Retrieve the authenticated user's profile information:

```go
ctx := context.Background()

user, err := client.GetUser(ctx, "access-token")
if err != nil {
    log.Fatalf("Failed to get user: %v", err)
}

fmt.Printf("User ID: %s\n", user.ID)
fmt.Printf("Name: %s\n", user.Name)
fmt.Printf("Email: %s\n", user.Email)
fmt.Printf("Avatar URL: %s\n", user.AvatarURL)
```

### Switch Role

Switch the user's active role and receive a new token with updated permissions:

```go
ctx := context.Background()

newToken, err := client.SwitchRole(ctx, "current-access-token", "admin")
if err != nil {
    log.Fatalf("Failed to switch role: %v", err)
}

fmt.Printf("New Access Token with role: %s\n", newToken.AccessToken)
```

### Check Access to Resource

Verify if the current user has access to a specific resource:

```go
ctx := context.Background()

allowed, err := client.CheckAccess(ctx, "access-token", "resource:read")
if err != nil {
    log.Fatalf("Failed to check access: %v", err)
}

if allowed {
    fmt.Println("User has access to the resource")
} else {
    fmt.Println("User does NOT have access to the resource")
}
```

## Data Types

### Config

```go
type Config struct {
    ClientID     string   // OAuth 2.0 client ID
    ClientSecret string   // OAuth 2.0 client secret
    RedirectURI  string   // Callback URL after authorization
    BaseURL      string   // API base URL
    Scopes       []string // OAuth scopes to request
}
```

### Token

```go
type Token struct {
    AccessToken  string `json:"access_token"`       // The access token
    RefreshToken string `json:"refresh_token"`      // The refresh token (optional)
    TokenType    string `json:"token_type"`         // Token type (e.g., "Bearer")
    ExpiresIn    int    `json:"expires_in"`         // Token expiry in seconds
    Scope        string `json:"scope"`              // Granted scopes (optional)
}
```

### User

```go
type User struct {
    ID        string `json:"id"`         // User's unique identifier
    Email     string `json:"email"`      // User's email address
    Name      string `json:"name"`       // User's display name
    AvatarURL string `json:"avatar_url"` // User's avatar URL (optional)
}
```

### IntrospectResponse

```go
type IntrospectResponse struct {
    Active    bool   `json:"active"`     // Whether the token is active
    Scope     string `json:"scope"`      // Token scopes
    ClientID  string `json:"client_id"`  // Client ID the token was issued to
    Username  string `json:"username"`   // Username associated with the token
    TokenType string `json:"token_type"` // Type of token
    Exp       int64  `json:"exp"`        // Expiration timestamp (Unix)
    Iat       int64  `json:"iat"`        // Issued at timestamp (Unix)
    Nbf       int64  `json:"nbf"`        // Not before timestamp (Unix)
    Sub       string `json:"sub"`        // Subject (user identifier)
    Aud       string `json:"aud"`        // Audience
    Iss       string `json:"iss"`        // Issuer
    Jti       string `json:"jti"`        // JWT ID
}
```

## Error Handling

All methods return an error as the last return value. Common error scenarios include:

```go
token, err := client.HandleCallback(ctx, r, expectedState)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "oauth error"):
        // Authorization was denied or failed
        log.Printf("OAuth error: %v", err)
    case strings.Contains(err.Error(), "missing 'code' parameter"):
        // Code parameter not found in callback
        log.Printf("Missing code: %v", err)
    case strings.Contains(err.Error(), "invalid state"):
        // CSRF protection triggered
        log.Printf("CSRF detected: %v", err)
    default:
        log.Printf("Unexpected error: %v", err)
    }
    return
}
```

## Complete Example

Here's a complete example of a web application using the Stimata SDK:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "sync"

    stimata "github.com/stimata-team-dev/stimata-sdk-go"
)

var (
    client *stimata.Client
    // In production, use a proper session store (e.g., Redis, database)
    stateStore = make(map[string]string)
    tokenStore = make(map[string]*stimata.Token)
    mu         sync.RWMutex
)

func main() {
    // Initialize the Stimata client
    client = stimata.New(stimata.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURI:  "http://localhost:8080/callback",
        BaseURL:      "https://auth.stimata.com/api",
        Scopes:       []string{"openid", "profile", "email"},
    })

    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/callback", callbackHandler)
    http.HandleFunc("/profile", profileHandler)
    http.HandleFunc("/logout", logoutHandler)

    fmt.Println("Server starting on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    html := `
        <h1>Stimata SDK Demo</h1>
        <p><a href="/login">Login with Stimata</a></p>
        <p><a href="/profile">View Profile</a></p>
        <p><a href="/logout">Logout</a></p>
    `
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, html)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    // Generate authorization URL with state
    authURL, state := client.AuthCodeURL()

    // Store state for CSRF verification (use session ID as key)
    sessionID := "demo-session" // In production, use actual session ID
    mu.Lock()
    stateStore[sessionID] = state
    mu.Unlock()

    // Redirect to authorization URL
    http.Redirect(w, r, authURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()
    sessionID := "demo-session" // In production, use actual session ID

    // Retrieve expected state
    mu.RLock()
    expectedState := stateStore[sessionID]
    mu.RUnlock()

    // Handle callback and exchange code for tokens
    token, err := client.HandleCallback(ctx, r, expectedState)
    if err != nil {
        http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusBadRequest)
        return
    }

    // Store token (use secure storage in production)
    mu.Lock()
    tokenStore[sessionID] = token
    delete(stateStore, sessionID) // Clean up state
    mu.Unlock()

    http.Redirect(w, r, "/profile", http.StatusFound)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()
    sessionID := "demo-session"

    // Get stored token
    mu.RLock()
    token := tokenStore[sessionID]
    mu.RUnlock()

    if token == nil {
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    // Fetch user profile
    user, err := client.GetUser(ctx, token.AccessToken)
    if err != nil {
        // Try to refresh token
        newToken, refreshErr := client.RefreshToken(ctx, token.RefreshToken)
        if refreshErr != nil {
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }

        // Update stored token
        mu.Lock()
        tokenStore[sessionID] = newToken
        mu.Unlock()

        // Retry with new token
        user, err = client.GetUser(ctx, newToken.AccessToken)
        if err != nil {
            http.Error(w, "Failed to fetch profile", http.StatusInternalServerError)
            return
        }
    }

    // Check access to a resource
    allowed, _ := client.CheckAccess(ctx, token.AccessToken, "profile:read")

    html := fmt.Sprintf(`
        <h1>User Profile</h1>
        <p><strong>ID:</strong> %s</p>
        <p><strong>Name:</strong> %s</p>
        <p><strong>Email:</strong> %s</p>
        <p><strong>Avatar:</strong> <img src="%s" width="50" /></p>
        <p><strong>Has profile:read access:</strong> %v</p>
        <p><a href="/">Home</a> | <a href="/logout">Logout</a></p>
    `, user.ID, user.Name, user.Email, user.AvatarURL, allowed)

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, html)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()
    sessionID := "demo-session"

    // Get stored token
    mu.RLock()
    token := tokenStore[sessionID]
    mu.RUnlock()

    if token != nil {
        // Revoke the token
        _ = client.Revoke(ctx, token.AccessToken)

        // Clear stored token
        mu.Lock()
        delete(tokenStore, sessionID)
        mu.Unlock()
    }

    http.Redirect(w, r, "/", http.StatusFound)
}
```

## Security Best Practices

1. **Secure Storage**: Store client secrets, access tokens, and refresh tokens securely. Never expose them in client-side code or logs.

2. **HTTPS**: Always use HTTPS in production to protect tokens in transit.

3. **State Parameter**: Always verify the state parameter in callbacks to prevent CSRF attacks. The SDK generates a cryptographically secure random state.

4. **Token Expiration**: Monitor token expiration using the `ExpiresIn` field and refresh tokens proactively.

5. **Token Revocation**: Revoke tokens when users log out or when tokens are no longer needed.

6. **Minimal Scopes**: Request only the scopes your application needs.

7. **Introspection**: Use token introspection to validate tokens before processing sensitive operations.

8. **Error Handling**: Handle errors gracefully without exposing sensitive information to users.

## API Endpoints Used

This SDK communicates with the following Stimata API endpoints:

| Method | Endpoint              | Description                          |
|--------|-----------------------|--------------------------------------|
| GET    | `/oauth/authorize`    | Authorization endpoint               |
| POST   | `/oauth/token`        | Token exchange endpoint              |
| POST   | `/oauth/introspect`   | Token introspection endpoint         |
| POST   | `/oauth/revoke`       | Token revocation endpoint            |
| GET    | `/auth/me`            | Get current user information         |
| POST   | `/oauth/switch-role`  | Switch user role                     |
| GET    | `/v1/check-access`    | Check access to a resource           |

## Requirements

- Go 1.18 or higher

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/stimata-team-dev/stimata-sdk-go).
