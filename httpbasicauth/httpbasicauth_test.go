package httpbasicauth

import (
	"testing"
	"strings"
	"github.com/google/go-cmp/cmp"
)

func TestLoad(t *testing.T) {
	type expect struct {
		Input     string
		wantErr   bool
		passwords map[string][]byte
	}
	expected := []expect{
		{
			Input:     "",
			wantErr:   false,
			passwords: map[string][]byte{},
		},
		{
			Input:     "# comment",
			wantErr:   false,
			passwords: map[string][]byte{},
		},
		{
			Input:     "junk",
			wantErr:   true,
			passwords: nil,
		},
		{
			Input:     "junk trash garbage",
			wantErr:   true,
			passwords: nil,
		},
		{
			Input:   "user $2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm\n",
			wantErr: false,
			passwords: map[string][]byte{
				"user": []byte("$2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm"),
			},
		},
		{
			// Should work without trailing newline.
			Input:   "user $2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm",
			wantErr: false,
			passwords: map[string][]byte{
				"user": []byte("$2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm"),
			},
		},
		{
			// Duplicate username.
			Input:   "user $2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm\nuser $2b$10$20zZVM2wu0Pw2AROUW/1V.l1gXZx/v0ezro53/fbZPrsE.gaBOmFe\n",
			wantErr: true,
			passwords: nil,
		},
		{
			// Two users.
			Input:   "user1 $2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm\nuser2 $2b$10$20zZVM2wu0Pw2AROUW/1V.l1gXZx/v0ezro53/fbZPrsE.gaBOmFe\n",
			wantErr: false,
			passwords: map[string][]byte{
				"user1": []byte("$2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm"),
				"user2": []byte("$2b$10$20zZVM2wu0Pw2AROUW/1V.l1gXZx/v0ezro53/fbZPrsE.gaBOmFe"),
			},
		},
	}
	for i, e := range expected {
		s := strings.NewReader(e.Input)
		got, err := loadPasswords(s)
		if (err != nil) != e.wantErr {
			t.Errorf("case %v: got error %q expected error %v", i, err, e.wantErr)
		}
		if diff := cmp.Diff(e.passwords, got); diff != "" {
			t.Errorf("loadPasswords() mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestCheck(t *testing.T) {
	ba, err := NewBasicAuthenticatorFromReader(strings.NewReader("user1 $2b$09$XDxv37mFio1MI0EnlFK2SOTrBL7BRYDOGw2nZnSbGibQ0TmxccvOm\nuser2 $2b$10$.T2oFl.3/LIDnakEaBKjbO25NLWlkczEpYkfvz0dbzVQZUQ1tZ4.."))
	if err != nil {
		t.Fatalf("NewBasicAuthenticatorFromReader: %v", err)
	}
	type expect struct {
		user string
		pass string
		wantErr bool
	}
	expected := []expect{
		{user: "", pass: "", wantErr: true},
		{user: "user", pass: "", wantErr: true},
		{user: "nobody", pass: "", wantErr: true},
		{user: "user1", pass: "wrong", wantErr: true},
		{user: "nobody", pass: "wrong", wantErr: true},
		{user: "user1", pass: "you-cracked-it", wantErr: false},
		{user: "user1", pass: "ou-cracked-it", wantErr: true},
		{user: "user1", pass: "you-cracked-i", wantErr: true},
		{user: "user1", pass: "1you-cracked-it", wantErr: true},
		{user: "user1", pass: "you-cracked-it1", wantErr: true},
		{user: "user1", pass: "You-cracked-it", wantErr: true},
		{user: "user2", pass: "you-cracked-it2", wantErr: false},
	}
	for i, e := range expected {
		err := ba.checkUserPassword(e.user, e.pass)
		if (err != nil) != e.wantErr {
			t.Errorf("case %v: got error %q expected error %v", i, err, e.wantErr)
		}
	}
}
