// Package httpbasicauth provides a simple interface to add HTTP basic
// authentication to a Go server using the usual http.HandlerFunc
// interface.
package httpbasicauth

import (
	"bufio"
	"context"
	"log"
	"net/http"
	"io"
	"os"
	"strings"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BasicAuthenticator represents an instance of a HTTP basic authenticator,
// including loaded passwords.
type BasicAuthenticator struct {
	passwordFile string
	passwords    map[string][]byte
}

func loadPasswords(r io.Reader) (map[string][]byte, error) {
	scanner := bufio.NewScanner(r)
	lineno := 0
	ret := map[string][]byte{}
	for scanner.Scan() {
		lineno++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		sp := strings.Fields(line)
		if len(sp) != 2 {
			return nil, fmt.Errorf("%v: invalid line", lineno)
		}
		_, ok := ret[sp[0]]
		if ok {
			return nil, fmt.Errorf("%v: duplicate user %v", lineno, sp[0])
		}
		ret[sp[0]] = []byte(sp[1])
	}
	err := scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	return ret, nil
}

func loadPasswordsFromFile(passwordFile string) (map[string][]byte, error) {
	f, err := os.Open(passwordFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ret, err := loadPasswords(f);
	if err != nil {
		return nil, fmt.Errorf("%v:%v", passwordFile, err)
	}
	return ret, nil
}

// NewBasicAuthenticatorFromFile creates a new HTTP basic authentication from
// the supplied password file.
func NewBasicAuthenticatorFromFile(passwordFile string) (*BasicAuthenticator, error) {
	passwords, err := loadPasswordsFromFile(passwordFile)
	if err != nil {
		return nil, err
	}
	return &BasicAuthenticator{
		passwordFile: passwordFile,
		passwords:    passwords,
	}, nil
}

// NewBasicAuthenticatorFromReader creates a new HTTP basic authenticator
// from the supplied reader.
func NewBasicAuthenticatorFromReader(r io.Reader) (*BasicAuthenticator, error) {
	passwords, err := loadPasswords(r)
	if err != nil {
		return nil, err
	}
	return &BasicAuthenticator{
		passwords:    passwords,
	}, nil
}

func (ba *BasicAuthenticator) checkUserPassword(username, password string) error {
	hashedPassword, ok := ba.passwords[username]
	if !ok {
		return fmt.Errorf("no such user %q", username)
	}
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return fmt.Errorf("failed password for user %q", username)
	}
	return nil
}

// Wrap wraps a http.HandlerFunc to request HTTP basic authentication.
// The inner handler will only be called after the user has been sucessfully
// authenticated. The authenticated username will be stored under the request
// context "user" key.
func (ba *BasicAuthenticator) Wrap(inner http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			log.Println(r.URL, "no auth")
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		err := ba.checkUserPassword(username, password)
		if err != nil {
			log.Printf("%s bad auth: %v", r.URL, err)
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Incorrect username/password", http.StatusUnauthorized)
			return
		}
		log.Println(r.URL, "by", username)
		ctx := context.WithValue(r.Context(), "user", username)
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}
