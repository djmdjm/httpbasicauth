This is a simple Go module for implementing HTTP basic auth in a server that
uses the standard Go `http.HandlerFunc` interface.

```go
basicAuth, err := httpauth.NewBasicAuthenticatorFromFile("data/passwd")          
if err != nil {                                                          
    log.Fatal(err)                                                   
}               
http.HandleFunc("/", basicAuth.Wrap(yourServerFunc))
```

Passwords are loaded once from the specified password file. This file contains
space separated `username hashed_password` pairs, one per line. Passwords are
hashed using the Bcrypt algorithm as implemented by the
[x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) package.

This package is still a work in progress.
