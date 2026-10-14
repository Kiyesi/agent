package packs

import (
	"os"
	"testing"
)

func TestPlacesLoad(t *testing.T) {
	p, err := LoadPlaces()
	if err != nil {
		t.Fatal(err)
	}
	ng := p.Country("ng")
	if ng == nil || ng.Name != "Nigeria" || len(ng.LocalDataCentres) == 0 {
		t.Fatalf("Nigeria pack = %+v", ng)
	}
	if p.CountryName("GB") != "UK" {
		t.Errorf("GB = %q", p.CountryName("GB"))
	}
}

func TestHostRegion(t *testing.T) {
	p, _ := LoadPlaces()
	for host, want := range map[string]string{
		"db-postgresql-lon1-12345-do-user-678-0.b.db.ondigitalocean.com": "London, UK",
		"checkout.abc123.eu-west-2.rds.amazonaws.com":                    "London, UK",
		"cache.xyz.af-south-1.cache.amazonaws.com":                       "Cape Town, South Africa",
		"my-bucket.s3.eu-central-1.amazonaws.com":                        "Frankfurt, Germany",
		"aws-0-eu-west-2.pooler.supabase.com":                            "London, UK",
		"s3.eu-central-003.backblazeb2.com":                              "Amsterdam, Netherlands",
		"fra1.digitaloceanspaces.com":                                    "Frankfurt, Germany",
	} {
		prov, r, ok := p.HostRegion(host)
		if !ok {
			t.Errorf("%s: no region found", host)
			continue
		}
		if got := p.Place(r); got != want {
			t.Errorf("%s (%s) = %q, want %q", host, prov.Name, got, want)
		}
	}
	for _, host := range []string{"cluster0.abcd.mongodb.net", "db.example.com", "localhost"} {
		if _, _, ok := p.HostRegion(host); ok {
			t.Errorf("%s should have no known region", host)
		}
	}
}

func TestRegionTrimsZones(t *testing.T) {
	p, _ := LoadPlaces()
	for vendor, zone := range map[string]string{"Hetzner": "fsn1-dc14", "Google": "europe-west2-b", "Amazon EC2": "eu-west-2a"} {
		prov := p.ProviderByVendor(vendor)
		if prov == nil {
			t.Fatalf("no provider for %s", vendor)
		}
		if _, _, ok := prov.Region(zone); !ok {
			t.Errorf("%s zone %s not found", vendor, zone)
		}
	}
}

func TestEmbeddedPlacesAreCurrent(t *testing.T) {
	for src, dst := range map[string]string{
		"../../../packs/regions.yaml":         "data/regions.yaml",
		"../../../packs/countries/names.yaml": "data/countries/names.yaml",
		"../../../packs/countries/ng.yaml":    "data/countries/ng.yaml",
	} {
		a, err := os.ReadFile(src)
		if err != nil {
			t.Skip("repository root not available")
		}
		b, _ := os.ReadFile(dst)
		if string(a) != string(b) {
			t.Errorf("%s is out of date: run go generate ./... in agent/", dst)
		}
	}
}
