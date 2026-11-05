package katana

import (
	"regexp"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// SECURITY: every crawl carries the destructive-link filter, with or
// without a web scope, and katana's regex (a Go regex, as here) keeps it
// away from logout, delete and reset links however they are spelled, while
// ordinary pages stay crawlable.
func TestDestructiveLinksNeverCrawled(t *testing.T) {
	plain := NewScanner().buildArgs("https://app.example.com", nil)
	scoped, _ := NewScanner().WithWebScope(&webscope.Scope{DenyPaths: []string{"/admin"}})
	for _, args := range [][]string{plain, scoped.(*Scanner).buildArgs("https://app.example.com", nil), NewDeepCrawler().buildArgs("https://app.example.com", nil)} {
		if !slices.Contains(flagValues(args, "-cos"), destructiveRegex) {
			t.Fatalf("no destructive filter in %q", args)
		}
	}
	re := regexp.MustCompile(destructiveRegex)
	for _, u := range []string{
		"https://app.example.com/logout", "https://app.example.com/account/Logout?next=/", "http://app.example.com:8080/sign-out",
		"https://app.example.com/log_out", "https://app.example.com/users/42/delete", "https://app.example.com/admin/deleteUser",
		"https://app.example.com/%6cogout", "https://app.example.com/index.php?action=remove&id=1", "https://app.example.com/reset-password",
		"https://app.example.com/api/v1/cache/purge", "https://app.example.com/drop", "https://app.example.com/db/dropTable",
		"https://app.example.com/server/shutdown", "https://app.example.com/subscription/cancel", "https://app.example.com/token/revoke",
		"https://app.example.com/UNSUBSCRIBE", "https://app.example.com/x/kill-session",
	} {
		if !re.MatchString(u) {
			t.Errorf("crawlable: %s", u)
		}
	}
	for _, u := range []string{
		"https://app.example.com/", "https://app.example.com/login", "https://app.example.com/ui/dropdown.js",
		"https://app.example.com/skills", "https://app.example.com/admin/users", "https://app.example.com/docs/api",
		"https://logout.example.com/", // the host is not the path
	} {
		if re.MatchString(u) {
			t.Errorf("not crawlable: %s", u)
		}
	}
}

// The results are filtered with the contract's exact check: a destructive
// URL katana reported anyway never reaches the platform.
func TestDestructiveResultsDropped(t *testing.T) {
	in := []core.DiscoveredURL{
		{URL: "https://app.example.com/"}, {URL: "https://app.example.com/logout"}, {URL: "https://app.example.com/a?do=delete"},
		{URL: "https://app.example.com/dropdown"}, {URL: "https://app.example.com/resetPassword"}, {URL: "://bad"},
	}
	var got []string
	for _, u := range withoutDestructive(in) {
		got = append(got, u.URL)
	}
	if want := []string{"https://app.example.com/", "https://app.example.com/dropdown"}; !slices.Equal(got, want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
}

// The deep crawler does not submit forms by default.
func TestDeepCrawlerKeepsFormFillOff(t *testing.T) {
	if NewDeepCrawler().FormFill || slices.Contains(NewDeepCrawler().buildArgs("https://app.example.com", nil), "-aff") {
		t.Fatal("the deep crawler fills forms")
	}
}
