package ocisync

import (
	"context"
	"testing"

	orasauth "oras.land/oras-go/v2/registry/remote/auth"
)

func TestNewCredentialFunc(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // don't pick up the user's containers auth.json

	tests := []struct {
		name string
		cfg  RegistryConfig
		want orasauth.Credential
	}{
		{name: "bearer token", cfg: RegistryConfig{Token: "secret"}, want: orasauth.Credential{AccessToken: "secret"}},
		{name: "username and token", cfg: RegistryConfig{Username: "me", Token: "secret"}, want: orasauth.Credential{Username: "me", Password: "secret"}},
		{name: "anonymous", cfg: RegistryConfig{}, want: orasauth.EmptyCredential},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentialFunc, err := newCredentialFunc(tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := credentialFunc(context.Background(), "registry.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("credential = %+v, want %+v", got, tt.want)
			}
		})
	}
}
