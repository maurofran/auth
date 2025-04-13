package token

import "fmt"

var ErrInvalidFormat = fmt.Errorf("invalid token format")

// Format represents a standard OAuth 2.0 token data format.
type Format struct {
	slug string
}

// ParseFormat parses a string and returns the corresponding Format value or FormatUnknown for unrecognized formats.
func ParseFormat(s string) (Format, error) {
	switch s {
	case FormatSelfContained.slug:
		return FormatSelfContained, nil
	case FormatReference.slug:
		return FormatReference, nil
	}
	return FormatUnknown, fmt.Errorf("%w: %q", ErrInvalidFormat, s)
}

func (f Format) MarshalText() ([]byte, error) {
	return []byte(f.slug), nil
}

func (f *Format) UnmarshalText(text []byte) error {
	var err error
	*f, err = ParseFormat(string(text))
	return err
}

func (f Format) String() string {
	return f.slug
}

var (
	FormatUnknown       = Format{slug: ""}
	FormatSelfContained = Format{slug: "self-contained"}
	FormatReference     = Format{slug: "reference"}
)
