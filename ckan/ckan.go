package ckan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-semver/semver"
	"strconv"
	"strings"
)

type specVersionContext int

const (
	intSpecType    string             = "int"
	stringSpecType string             = "string"
	SpecContext    specVersionContext = 1
)

type SpecVersion struct {
	specType    string // "int" or "string"
	specVersion interface{}
}

func NewSpecVersion(min string) SpecVersion {
	var ckanSpec SpecVersion
	if _, err := strconv.ParseInt(min, 10, 8); err == nil {
		ckanSpec.specType = intSpecType
		ckanSpec.specVersion = 1
	}
	var minVer string
	if strings.HasPrefix(min, "v") {
		minVer = min[1:] + ".0"
	} else {
		minVer = min + ".0"
	}
	_, err := semver.NewVersion(minVer)
	if err == nil {
		ckanSpec.specType = stringSpecType
		ckanSpec.specVersion = min
	}
	return ckanSpec
}

func (spec SpecVersion) AtLeast(v interface{}) bool {
	if val, ok := v.(int); ok {
		if val < 1 {
			return false
		}
		return true
	} // get them non-strings out of the way
	if val, ok := v.(string); ok {
		if strings.HasPrefix(val, "v") {
			val = val[1:]
		}
		switch spec.specType {
		case intSpecType:
			return true
		case stringSpecType:
			if w, ok := spec.specVersion.(string); ok {
				if strings.HasPrefix(w, "v") {
					w = w[1:]
				}
				w = fmt.Sprintf("%s.0", w)
				vSpec := semver.New(w)
				val = fmt.Sprintf("%s.0", val)
				vCheck := semver.New(val)
				return vSpec.Compare(*vCheck) >= 0
			}
		}
	}
	return false
}

func (spec SpecVersion) MarshalJSON() ([]byte, error) {
	// we do not want to use the json.Marshal on an interface{} type
	// as this triggers a slow type conversion routine
	switch spec.specType {
	case intSpecType:
		// it doesn't matter what you think! a spec is a spec!
		return json.Marshal(1)
	case stringSpecType:
		if v, ok := spec.specVersion.(string); ok {
			return json.Marshal(v)
		} else {
			return make([]byte, 0), fmt.Errorf("you did a bad")
		}
	default:
		return make([]byte, 0), fmt.Errorf("you did a bad")
	}
}

type License struct {
	isList  bool
	license interface{}
}

func NewLicense(isList bool, license interface{}) License {
	var L License
	L.isList = isList
	L.license = license
	return L
}

func (lic License) MarshalJSON() ([]byte, error) {
	var b []byte
	var err error
	// Speed things up a little
	if lic.isList {
		b, err = json.Marshal(lic.license)
	} else {
		if v, ok := lic.license.(string); ok {
			b, err = json.Marshal(v)
		} else {
			b, err = json.Marshal(v)
		}
	}
	return b, err
}

type PackageVersion struct {
	epoch      uint
	modVersion string
}

func NewPackageVersion(epoch uint, modVersion string) PackageVersion {
	var P PackageVersion
	P.epoch = epoch
	P.modVersion = modVersion
	return P
}

func (ver PackageVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%d:%s", ver.epoch, ver.modVersion))
}

type ckanInstallStep struct {
	installType     string
	installFileName string
	installTo       string
	installOptions  map[string]interface{} // TODO: Implement marshal
	spec            SpecVersion            // TODO: context? something
}

func NewInstallStep(installType, installFrom, installTarget string, spec SpecVersion) *ckanInstallStep {
	var cki *ckanInstallStep
	cki = new(ckanInstallStep)
	cki.installType = installType
	cki.installFileName = installFrom
	cki.installTo = installTarget
	cki.spec = spec
	return cki
}

func (ckt *ckanInstallStep) getOpt(s string) (func() (interface{}, error), bool) {
	v, ok := ckt.installOptions[s]
	if ok {
		return func() (interface{}, error) {
			var i interface{}
			i = v
			return i, nil
		}, ok
	}
	return func() (interface{}, error) { return struct{}{}, nil }, false
}

func (ckt *ckanInstallStep) FileName() string {
	return ckt.installFileName
}

func (ckt *ckanInstallStep) As() (func() (string, error), bool) {
	if !ckt.spec.AtLeast("v1.18") {
		return func() (string, error) { return "", nil }, false
	}
	if f, ok := ckt.getOpt("as"); ok {
		val, err := f()
		if v, ok := val.(string); ok {
			return func() (string, error) { return v, nil }, true
		} else {
			if err != nil {
				return func() (string, error) { return "", err }, false
			}
		}
	}
	return func() (string, error) { return "", nil }, false
}

func (ckt *ckanInstallStep) Filter() (func() (interface{}, error), bool) {
	return ckt.getOpt("filter")
}
func (ckt *ckanInstallStep) FilterRegexp() (func() (interface{}, error), bool) {
	return ckt.getOpt("filter_regexp")
}
func (ckt *ckanInstallStep) IncludeOnly() (func() (interface{}, error), bool) {
	if !ckt.spec.AtLeast("v1.24") {
		return func() (interface{}, error) { return struct{}{}, nil }, false
	}
	return ckt.getOpt("include_only")
}
func (ckt *ckanInstallStep) IncludeOnlyRegexp() (func() (interface{}, error), bool) {
	if !ckt.spec.AtLeast("v1.24") {
		return func() (interface{}, error) { return struct{}{}, nil }, false
	}
	return ckt.getOpt("include_only_regexp")
}
func (ckt *ckanInstallStep) FindMatchesFiles() (func() (bool, error), bool) {
	if !ckt.spec.AtLeast("v1.16") {
		return func() (bool, error) { return false, nil }, false
	}
	if f, ok := ckt.getOpt("find_matches_files"); ok {
		val, err := f()
		if err != nil {
			if v, ok := val.(bool); ok {
				return func() (bool, error) {
					return v, nil
				}, true
			}
		}
		return func() (bool, error) { return false, err }, false
	}
	return func() (bool, error) { return false, nil }, false
}

func (ckt *ckanInstallStep) fileMarshalJSON() ([]byte, error) {
	var b []byte
	buffer := bytes.NewBufferString("")
	var err error
	jsonVal, err := json.Marshal(ckt.FileName())
	if err != nil {
		return make([]byte, 0), err
	}
	buffer.WriteString(fmt.Sprintf("\"file\":%s,", string(jsonVal)))
	b = buffer.Bytes()
	return b, err
}

func (ckt *ckanInstallStep) findOrRegexpMarshalJSON() ([]byte, error) {
	var b []byte
	var err error
	jsonVal, err := json.Marshal(ckt.FileName())
	if err != nil {
		return make([]byte, 0), err
	}
	var bFind []byte
	buffer := bytes.NewBuffer(bFind)
	buffer.WriteString(fmt.Sprintf("\"%s\":%s,", ckt.installType, string(jsonVal)))
	b = append(b, buffer.Bytes()...)
	return b, err
}

func (ckt *ckanInstallStep) optsMarshalJSON() ([]byte, error) {
	var b []byte
	var err error
	if v, ok := ckt.As(); ok {
		v, _ := v()
		jsonVal, _ := json.Marshal(v)
		buffer := bytes.NewBufferString("\"as\":")
		buffer.WriteString(fmt.Sprintf("%s,", string(jsonVal)))
		b = append(b, buffer.Bytes()...)
	}
	return b, err
}

func (ckt *ckanInstallStep) MarshalJSON() ([]byte, error) {
	var b []byte
	b = append(b, byte('{'))
	var err error
	switch ckt.installType {
	case "file":
		jsonVal, err := ckt.fileMarshalJSON()
		if err != nil {
			panic(err)
		}
		b = append(b, jsonVal...)
	case "find":
		if !ckt.spec.AtLeast("v1.4") {
			break // wat? no.
		}
		jsonVal, err := ckt.findOrRegexpMarshalJSON()
		if err != nil {
			panic(err)
		}
		b = append(b, jsonVal...)
	case "find_regexp":
		if !ckt.spec.AtLeast("v1.10") {
			break // wat? no.
		}
		jsonVal, err := ckt.findOrRegexpMarshalJSON()
		if err != nil {
			panic(err)
		}
		b = append(b, jsonVal...)
	default:
		panic(fmt.Errorf("unknown installType: %s", ckt.installType))
	}
	optsJson, err := ckt.optsMarshalJSON()
	if err == nil {
		b = append(b, optsJson...)
	}
	jsonVal, err := json.Marshal(ckt.installTo)
	if err == nil {
		var bInstallTo []byte
		buffer := bytes.NewBuffer(bInstallTo)
		buffer.WriteString(fmt.Sprintf("\"install_to\":%s", string(jsonVal)))
		b = append(b, buffer.Bytes()...)
	}
	b = append(b, '}')
	return b, err
}

func (ckt *ckanInstallStep) SetOption(s string, i interface{}) (InstallStep, error) {
	var cktIface InstallStep
	var err error
	if ckt.installOptions == nil {
		ckt.installOptions = make(map[string]interface{})
	}
	ckt.installOptions[s] = i
	cktIface = ckt
	return cktIface, err
}

var _ InstallStep = &ckanInstallStep{}

type InstallStep interface {
	As() (func() (string, error), bool)
	Filter() (func() (interface{}, error), bool)
	FilterRegexp() (func() (interface{}, error), bool)
	IncludeOnly() (func() (interface{}, error), bool)
	IncludeOnlyRegexp() (func() (interface{}, error), bool)
	FindMatchesFiles() (func() (bool, error), bool)
	SetOption(string, interface{}) (InstallStep, error)
	json.Marshaler // Requirement #1
}

type BaseModule struct {
	SpecVersion      SpecVersion           `json:"spec_version"` // TODO: Implement comparisons
	Name             string                `json:"name"`
	Abstract         string                `json:"abstract"`
	Identifier       string                `json:"identifier"` // TODO: implement ValidIdentifier()
	Download         string                `json:"download"`   // TODO: evaluate url.URL
	License          License               `json:"license"`    // TODO: implement ValidLicense()
	Version          PackageVersion        `json:"version"`
	Install          []InstallStep         `json:"install,omitempty"`
	Comment          string                `json:"comment,omitempty"`
	Author           interface{}           `json:"author,omitempty"`
	Description      string                `json:"description,omitempty"`        // TODO: implement a better way
	ReleaseStatus    string                `json:"release_status,omitempty"`     // TODO: implement detection of stability
	KSPVersion       string                `json:"ksp_version,omitempty"`        // TODO: version checking
	KSPVersionMin    string                `json:"ksp_version_min,omitempty"`    // TODO: version checking
	KSPVersionMax    string                `json:"ksp_version_max,omitempty"`    // TODO: version checking
	KSPVersionStrict bool                  `json:"ksp_version_strict,omitempty"` // TODO: version checking
	Tags             []string              `json:"tags,omitempty"`
	Depends          []*ModuleRelationship `json:"depends,omitempty"`
	Recommends       []*ModuleRelationship `json:"recommends,omitempty"`
	Suggests         []*ModuleRelationship `json:"suggests,omitempty"`
	Supports         []*ModuleRelationship `json:"supports,omitempty"`
	Conflicts        []*ModuleRelationship `json:"conflicts,omitempty"`
	ReplacedBy       []*ModuleRelationship `json:"replaced_by,omitempty"`
	Resources        *Resources            `json:"resources,omitempty"`
	Kind             string                `json:"kind,omitempty"`
	Provides         []string              `json:"provides,omitempty"` // TODO: implement identifiers check
	DownloadSize     uint                  `json:"download_size,omitempty"`
	DownloadHash     *DownloadHash         `json:"download_hash,omitempty"`
	ContentType      string                `json:"download_content_type,omitempty"`
}

type Resources struct {
	Homepage   string `json:"homepage,omitempty"`
	Bugtracker string `json:"bugtracker,omitempty"`
	Repository string `json:"repository,omitempty"`
	Ci         string `json:"ci,omitempty"`
	Spacedock  string `json:"spacedock,omitempty"`
	Curse      string `json:"curse,omitempty"`
}

type DownloadHash struct {
	Sha1   string `json:"sha1"`
	Sha256 string `json:"sha256"`
}

type ModuleRelationship struct {
	Name       string                `json:"name"`
	MinVersion string                `json:"min_version,omitempty"`
	MaxVersion string                `json:"max_version,omitempty"`
	Version    string                `json:"version,omitempty"`
	AnyOf      []*ModuleRelationship `json:"any_of,omitempty"`
}

func (b *BaseModule) GetSpecVersion() SpecVersion { return b.SpecVersion }
func (b *BaseModule) SetSpecVersion(version SpecVersion) error {
	b.SpecVersion = version
	return nil
}
func (b *BaseModule) GetName() string { return b.Name }
func (b *BaseModule) SetName(s string) error {
	b.Name = s
	return nil
}
func (b *BaseModule) GetDownload() string { return b.Download }
func (b *BaseModule) SetDownload(s string) error {
	b.Download = s
	return nil
}

type baseModuleJSON struct {
	BaseModule
}

func (b *BaseModule) MarshalJSON() ([]byte, error) {
	bw := baseModuleJSON{
		*b,
	}
	return json.Marshal(bw)
}

// Module implements a basic interface for plugins - this is a work-in-progress
type Module interface {
	GetSpecVersion() SpecVersion
	SetSpecVersion(SpecVersion) error
	GetName() string
	SetName(string) error
	GetDownload() string
	SetDownload(string) error
	json.Marshaler
} // TODO: Figure out the "must-haves" and implement With<Value> for options at init and plugin capabilities

var _ Module = &BaseModule{}

func WithName(s string) func(Module) Module {
	return func(m Module) Module {
		err := m.SetName(s)
		if err != nil {
			panic(err)
		}
		return m
	}
}

func WithDownload(s string) func(Module) Module {
	return func(m Module) Module {
		err := m.SetDownload(s)
		if err != nil {
			panic(err)
		}
		return m
	}
}

func NewCKANModule(spec SpecVersion, opts ...func(Module) Module) (Module, error) {
	var bp Module = &BaseModule{}
	var err error
	err = bp.SetSpecVersion(spec)
	if err != nil {
		return bp, err
	}
	if len(opts) > 0 {
		for _, fn := range opts {
			bp = fn(bp) // TODO: error handling
		}
	}
	return bp, err
}

func main() {
}
