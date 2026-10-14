package packs

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed data/regions.yaml data/countries
var locationFiles embed.FS

// Region is where a provider's region is.
type Region struct {
	City    string `yaml:"city"`
	Country string `yaml:"country"`
}

// Provider is a cloud or storage provider and its regions.
type Provider struct {
	ID        string            `yaml:"id"`
	Name      string            `yaml:"name"`
	Vendors   []string          `yaml:"vendors"`
	CloudInit []string          `yaml:"cloud_init"`
	Hosts     []string          `yaml:"hosts"`
	Regions   map[string]Region `yaml:"regions"`

	hostREs []*regexp.Regexp
}

// Country is a country rule pack.
type Country struct {
	Code             string   `yaml:"code"`
	Name             string   `yaml:"name"`
	Rule             string   `yaml:"rule"`
	RuleSource       string   `yaml:"rule_source"`
	LocalDataCentres []string `yaml:"local_data_centres"`
}

// Places holds the providers, the country names and the rule packs.
type Places struct {
	Providers []*Provider
	names     map[string]string
	countries map[string]*Country
}

var (
	placesOnce sync.Once
	places     *Places
	placesErr  error
)

// LoadPlaces returns the built-in region table and country packs.
func LoadPlaces() (*Places, error) {
	placesOnce.Do(func() { places, placesErr = parsePlaces() })
	return places, placesErr
}

func parsePlaces() (*Places, error) {
	var regions struct {
		Providers []*Provider `yaml:"providers"`
	}
	data, err := locationFiles.ReadFile("data/regions.yaml")
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &regions); err != nil {
		return nil, fmt.Errorf("reading regions.yaml: %w", err)
	}
	p := &Places{Providers: regions.Providers, names: map[string]string{}, countries: map[string]*Country{}}
	for _, prov := range p.Providers {
		for _, h := range prov.Hosts {
			re, err := regexp.Compile(h)
			if err != nil {
				return nil, fmt.Errorf("regions.yaml, %s: %w", prov.ID, err)
			}
			if re.SubexpIndex("region") < 0 {
				return nil, fmt.Errorf("regions.yaml, %s: pattern %q has no region group", prov.ID, h)
			}
			prov.hostREs = append(prov.hostREs, re)
		}
		for code, r := range prov.Regions {
			if r.City == "" || len(r.Country) != 2 {
				return nil, fmt.Errorf("regions.yaml, %s %s: needs a city and a 2-letter country", prov.ID, code)
			}
		}
	}
	names, err := locationFiles.ReadFile("data/countries/names.yaml")
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(names, &p.names); err != nil {
		return nil, fmt.Errorf("reading countries/names.yaml: %w", err)
	}
	entries, err := locationFiles.ReadDir("data/countries")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Name() == "names.yaml" {
			continue
		}
		data, err := locationFiles.ReadFile("data/countries/" + e.Name())
		if err != nil {
			return nil, err
		}
		var c Country
		if err := yaml.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("reading countries/%s: %w", e.Name(), err)
		}
		if c.Code == "" || c.Name == "" || c.Rule == "" {
			return nil, fmt.Errorf("countries/%s needs a code, a name and a rule", e.Name())
		}
		p.countries[strings.ToUpper(c.Code)] = &c
	}
	for _, prov := range p.Providers {
		for code, r := range prov.Regions {
			if p.names[r.Country] == "" {
				return nil, fmt.Errorf("regions.yaml, %s %s: country %s has no name in countries/names.yaml", prov.ID, code, r.Country)
			}
		}
	}
	return p, nil
}

// CountryName returns the short name for an ISO code, or the code itself.
func (p *Places) CountryName(code string) string {
	if n := p.names[strings.ToUpper(code)]; n != "" {
		return n
	}
	return strings.ToUpper(code)
}

// Country returns the rule pack for a country, or nil when there is none.
func (p *Places) Country(code string) *Country { return p.countries[strings.ToUpper(code)] }

// ProviderByVendor finds the provider whose DMI vendor matches.
func (p *Places) ProviderByVendor(vendor string) *Provider {
	vendor = strings.TrimSpace(vendor)
	for _, prov := range p.Providers {
		for _, v := range prov.Vendors {
			if strings.EqualFold(v, vendor) {
				return prov
			}
		}
	}
	return nil
}

// ProviderByCloudInit finds the provider for a cloud-init cloud name.
func (p *Places) ProviderByCloudInit(name string) *Provider {
	for _, prov := range p.Providers {
		for _, v := range prov.CloudInit {
			if strings.EqualFold(v, name) {
				return prov
			}
		}
	}
	return nil
}

// Region looks up a region code, also trying it without a zone suffix, as
// in eu-west-2a, europe-west2-b and fsn1-dc14.
func (prov *Provider) Region(code string) (Region, string, bool) {
	code = strings.ToLower(strings.TrimSpace(code))
	for _, c := range []string{code, trimZone(code)} {
		if r, ok := prov.Regions[c]; ok {
			return r, c, true
		}
	}
	return Region{}, "", false
}

var zoneSuffix = regexp.MustCompile(`(-dc\d+|-[a-z]|[a-z])$`)

func trimZone(code string) string { return zoneSuffix.ReplaceAllString(code, "") }

// HostRegion finds a provider and region from a hostname such as
// db-postgresql-lon1-123-do-user-1.db.ondigitalocean.com.
func (p *Places) HostRegion(host string) (*Provider, Region, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, prov := range p.Providers {
		for _, re := range prov.hostREs {
			m := re.FindStringSubmatch(host)
			if m == nil {
				continue
			}
			if r, _, ok := prov.Region(m[re.SubexpIndex("region")]); ok {
				return prov, r, true
			}
		}
	}
	return nil, Region{}, false
}

// Place writes a region the way the report shows it: "London, UK".
func (p *Places) Place(r Region) string {
	name := p.CountryName(r.Country)
	if strings.EqualFold(r.City, name) {
		return name
	}
	return r.City + ", " + name
}
