package aaguids

// Metadata is a set of basic metatadata about the authenticator.
// It is based on: https://github.com/passkeydeveloper/passkey-authenticator-aaguids
type Metadata struct {
	// Name is the name of the authenticator.
	Name string `json:"name" yaml:"name" mapstructure:"name"`
	// SVG base64 encoded as a data URI.
	IconDark string `json:"icon_dark,omitempty" yaml:"icon_dark,omitempty" mapstructure:"icon_dark,omitempty"`
	// SVG base64 encoded as a data URI.
	IconLight string `json:"icon_light,omitempty" yaml:"icon_light,omitempty" mapstructure:"icon_light,omitempty"`
}
