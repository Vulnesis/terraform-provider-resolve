package provider

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/vulnetix/terraform-provider-resolve/internal/client"
)

// The provider offers exactly the kinds the engine applies: an unserved
// kind's resource would fail every apply with unknown kind.
func TestResourcesAreServedKindsOnly(t *testing.T) {
	p := New("test")()
	got := map[string]bool{}
	for _, f := range p.Resources(context.Background()) {
		var resp resource.MetadataResponse
		f().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "vulnetix"}, &resp)
		got[resp.TypeName] = true
	}
	for _, k := range generatedKinds {
		if !got["vulnetix_"+k.TypeName] {
			t.Errorf("served kind %s has no resource", k.Kind)
		}
	}
	for _, k := range generatedKindsUnserved {
		if got["vulnetix_"+k.TypeName] {
			t.Errorf("unserved kind %s is offered as a resource", k.Kind)
		}
	}
	if len(got) != len(generatedKinds) {
		t.Errorf("%d resources for %d served kinds", len(got), len(generatedKinds))
	}
}

// The README and the registry's index page list every served resource and
// every data source.
func TestReadmeAndIndexListEverything(t *testing.T) {
	names := []string{}
	for _, k := range generatedKinds {
		names = append(names, "vulnetix_"+k.TypeName)
	}
	for _, f := range New("test")().DataSources(context.Background()) {
		var resp datasource.MetadataResponse
		f().Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "vulnetix"}, &resp)
		names = append(names, resp.TypeName)
	}
	for _, file := range []string{"../../README.md", "../../templates/index.md.tmpl"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if !strings.Contains(string(b), "`"+n+"`") {
				t.Errorf("%s does not list %s", file, n)
			}
		}
	}
}

// The credential rules: an ApiKey with its organisation, or a bearer token,
// never both; none is a warning, not an error.
func TestCheckCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		apiKey, orgID, token string
		errors, warnings     int
	}{
		"api key and org":    {apiKey: "k", orgID: "o"},
		"bearer token":       {token: "t"},
		"bearer with org id": {token: "t", orgID: "o"},
		"api key and token":  {apiKey: "k", orgID: "o", token: "t", errors: 1},
		"api key only":       {apiKey: "k", errors: 1},
		"api key with token": {apiKey: "k", token: "t", errors: 1},
		"org id only":        {orgID: "o", errors: 1},
		"nothing configured": {warnings: 1},
	} {
		t.Run(name, func(t *testing.T) {
			d := checkCredentials(tc.apiKey, tc.orgID, tc.token)
			if d.ErrorsCount() != tc.errors || d.WarningsCount() != tc.warnings {
				t.Errorf("%d errors and %d warnings, want %d and %d: %v", d.ErrorsCount(), d.WarningsCount(), tc.errors, tc.warnings, d)
			}
		})
	}
}

// The brand only moves the default endpoint: Vulnesis (the default) maps
// client.DefaultEndpoint onto vulnes.is, Vulnetix keeps it, and an explicit
// endpoint (argument or VULNETIX_ENDPOINT) always wins.
func TestBrandEndpoint(t *testing.T) {
	for name, tc := range map[string]struct {
		arg             types.String
		envBrand, alias string
		configured      string
		want            string
	}{
		"default":                       {arg: types.StringNull(), want: "https://www.vulnes.is/api/site/v1"},
		"argument vulnetix":             {arg: types.StringValue("vulnetix"), want: client.DefaultEndpoint},
		"argument vulnesis":             {arg: types.StringValue("vulnesis"), want: "https://www.vulnes.is/api/site/v1"},
		"argument any case":             {arg: types.StringValue("Vulnesis"), want: "https://www.vulnes.is/api/site/v1"},
		"env vulnesis":                  {arg: types.StringNull(), envBrand: "vulnesis", want: "https://www.vulnes.is/api/site/v1"},
		"env alias":                     {arg: types.StringNull(), alias: "vulnesis", want: "https://www.vulnes.is/api/site/v1"},
		"env vulnetix":                  {arg: types.StringNull(), envBrand: "vulnetix", want: client.DefaultEndpoint},
		"env garbage":                   {arg: types.StringNull(), envBrand: "acme", want: "https://www.vulnes.is/api/site/v1"},
		"argument wins over env":        {arg: types.StringValue("vulnetix"), envBrand: "vulnesis", want: client.DefaultEndpoint},
		"unknown argument falls to env": {arg: types.StringUnknown(), envBrand: "vulnesis", want: "https://www.vulnes.is/api/site/v1"},
		"explicit endpoint wins":        {arg: types.StringValue("vulnesis"), configured: "https://staging.example/v1", want: "https://staging.example/v1"},
		"explicit vulnetix endpoint":    {arg: types.StringValue("vulnesis"), configured: client.DefaultEndpoint, want: client.DefaultEndpoint},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(EnvBrand, tc.envBrand)
			t.Setenv(EnvBrandAlias, tc.alias)
			if got := defaultEndpoint(tc.configured, resolveBrand(tc.arg)); got != tc.want {
				t.Errorf("endpoint %q, want %q", got, tc.want)
			}
		})
	}
}

// The brand argument is optional and validated.
func TestBrandArgument(t *testing.T) {
	var resp provider.SchemaResponse
	(&vulnetixProvider{}).Schema(context.Background(), provider.SchemaRequest{}, &resp)
	a, ok := resp.Schema.Attributes["brand"].(schema.StringAttribute)
	if !ok {
		t.Fatal("no brand string argument")
	}
	if !a.Optional || a.Required || len(a.Validators) == 0 {
		t.Errorf("brand must be optional and validated: %+v", a)
	}
}

// The credential arguments say who may use them.
func TestCredentialDescriptions(t *testing.T) {
	var resp provider.SchemaResponse
	(&vulnetixProvider{}).Schema(context.Background(), provider.SchemaRequest{}, &resp)
	for _, name := range []string{"api_key", "org_id", "token"} {
		if resp.Schema.Attributes[name] == nil {
			t.Fatalf("no %s argument", name)
		}
	}
	for _, name := range []string{"api_key", "token"} {
		a := resp.Schema.Attributes[name]
		if !a.IsSensitive() {
			t.Errorf("%s is not sensitive", name)
		}
		d := a.GetMarkdownDescription()
		for _, want := range []string{"owner or admin", "service account", "member", "403"} {
			if !strings.Contains(d, want) {
				t.Errorf("%s description does not mention %q: %s", name, want, d)
			}
		}
	}
}
