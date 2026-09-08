package catalogselection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

func DecodeExact(raw []byte, target any) error {
	kind := reflect.TypeOf(target)
	if kind == nil || kind.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return errors.New("selected artifact decoder requires an exact destination")
	}
	if err := ValidateJSON(raw, kind.Elem(), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("selected artifact has trailing JSON")
	}
	return nil
}

func ValidateJSON(raw []byte, kind reflect.Type, depth int) error {
	if depth > 32 {
		return errors.New("selected artifact JSON is too deep")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return errors.New("selected artifact JSON is empty")
	}
	if kind != nil && kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if kind != nil && bytes.Equal(trimmed, []byte("null")) {
		return errors.New("selected typed artifact field is null")
	}
	if trimmed[0] == '[' {
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		var element reflect.Type
		if kind != nil && (kind.Kind() == reflect.Slice || kind.Kind() == reflect.Array) {
			element = kind.Elem()
		}
		for _, value := range values {
			if err := ValidateJSON(value, element, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if trimmed[0] != '{' {
		if !json.Valid(raw) {
			return errors.New("selected artifact JSON is malformed")
		}
		return nil
	}
	fields := make(map[string]reflect.Type)
	if kind != nil && kind.Kind() == reflect.Struct {
		for i := 0; i < kind.NumField(); i++ {
			f := kind.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	_, _ = d.Token()
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return errors.New("selected artifact has duplicate or malformed fields")
		}
		seen[key] = true
		// The index and rich metadata intentionally allow display fields, but
		// their identity members must still have one exact spelling.
		for _, identity := range []string{"apps", "appId", "packageId"} {
			if key != identity && strings.EqualFold(key, identity) {
				return errors.New("selected artifact has an aliased identity field")
			}
		}
		fieldType, known := fields[key]
		if len(fields) > 0 && !known {
			return fmt.Errorf("selected artifact has unknown or aliased field %q", key)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return err
		}
		if err := ValidateJSON(value, fieldType, depth+1); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("selected artifact has trailing JSON")
	}
	return nil
}
