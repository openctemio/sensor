package nuclei

import (
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/egressenv"
)

// The finding check declares features.web_scope: validation and retest
// jobs carry the job's web scope like scans.
func TestValidateToolDeclaresWebScope(t *testing.T) {
	if ValidateToolManifest.Features == nil || !ValidateToolManifest.Features.WebScope {
		t.Fatal("nuclei-validate does not declare features.web_scope")
	}
}

// SECURITY: a web-scoped re-verify or retest runs only confined to the
// task's forwarder; unconfined it is refused, never run unrestricted. The
// flag comes from the task, never from the sensor's configuration.
func TestApplyTaskWebScope(t *testing.T) {
	scoped := tool.Task{WebScope: &webscope.Scope{DenyPaths: []string{"/admin"}}}
	t.Setenv(egressenv.EnvProxy, "")
	var o ValidateOptions
	err := applyTaskWebScope(&o, scoped)
	var te *tool.Error
	if !errors.As(err, &te) || te.Class != tool.RefusedByPolicy {
		t.Fatalf("unconfined web-scoped task: %v, want refused", err)
	}
	t.Setenv(egressenv.EnvProxy, "http://127.0.0.1:3128")
	if err := applyTaskWebScope(&o, scoped); err != nil || !o.WebScoped {
		t.Fatalf("confined: %v, web scoped %v", err, o.WebScoped)
	}
	o.WebScoped = true
	if err := applyTaskWebScope(&o, tool.Task{}); err != nil || o.WebScoped {
		t.Fatalf("a task without a scope: %v, web scoped %v", err, o.WebScoped)
	}
}

// A web-scoped re-verify goes through the forwarder's relay and leaves out
// the template types the forwarder cannot read as HTTP, as a scan does.
func TestValidateArgsWebScoped(t *testing.T) {
	t.Setenv(egressenv.EnvProxy, "http://127.0.0.1:3128")
	args, err := buildValidateArgs(ValidateOptions{Target: "https://app.example", TemplateID: "clean-detect", WebScoped: true})
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(args, "-proxy")
	if i < 0 || args[i+1] != "http://127.0.0.1:3128" {
		t.Fatalf("no relay proxy: %v", args)
	}
	if j := slices.Index(args, "-ept"); j < 0 || args[j+1] != webScopeExcludedTypes {
		t.Fatalf("no excluded types: %v", args)
	}
	plain, _ := buildValidateArgs(ValidateOptions{Target: "https://app.example", TemplateID: "clean-detect"})
	if slices.Contains(plain, "-ept") {
		t.Fatalf("an unscoped re-verify got web-scope flags: %v", plain)
	}
}
