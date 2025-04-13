package authentication

import (
	"errors"
	"fmt"
)

// ErrInvalidMethod is the erro returned when an invalid method is provided to the ParseMethod function.
var ErrInvalidMethod = errors.New("invalid method")

// Method represents the various methods that can be used for client authentication in the system.
type Method struct {
	slug string
}

// ParseMethod converts the given slug string into its corresponding Method type or returns an error for invalid slugs.
func ParseMethod(slug string) (Method, error) {
	switch slug {
	case MethodHeader.slug:
		return MethodHeader, nil
	case MethodForm.slug:
		return MethodForm, nil
	case MethodQuery.slug:
		return MethodQuery, nil
	}
	return MethodUnknown, fmt.Errorf("%w: %q", ErrInvalidMethod, slug)
}

func (t Method) MarshalText() ([]byte, error) {
	return []byte(t.slug), nil
}

func (t *Method) UnmarshalText(text []byte) error {
	var err error
	*t, err = ParseMethod(string(text))
	return err
}

func (t Method) String() string {
	return t.slug
}

var (
	MethodUnknown = Method{slug: ""}
	MethodHeader  = Method{slug: "header"}
	MethodForm    = Method{slug: "form"}
	MethodQuery   = Method{slug: "query"}
)
