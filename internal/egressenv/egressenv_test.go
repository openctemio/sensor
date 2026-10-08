package egressenv

import "testing"

func TestEgressEnv(t *testing.T) {
	t.Setenv(EnvProxy, "")
	if Confined() || Proxy() != "" || SOCKSAddr() != "" || Resolver() != "" {
		t.Fatal("not confined: nothing is set")
	}
	t.Setenv(EnvProxy, "http://127.0.0.1:1080")
	if !Confined() || SOCKSAddr() != "127.0.0.1:1080" || Resolver() != "127.0.0.1" {
		t.Fatalf("confined: %q %q %q", Proxy(), SOCKSAddr(), Resolver())
	}
}
