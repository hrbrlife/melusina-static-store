package estateprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxJSONDepth bounds nesting. The deepest legitimate path is
// profile → policySuccession[] → toPolicy → signers[] → signer.
const maxJSONDepth = 8

var safeIntegerPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

// decodeStrict decodes exactly one document with no ambiguity encoding/json
// would otherwise allow. It refuses, by name and JSON path: an empty or
// oversized input, invalid UTF-8, excess nesting, a duplicate key at any
// depth, an unknown or case-aliased key, a MISSING key (every key of every
// object is required; nothing is optional and nothing defaults), null, a value
// of the wrong JSON type, a number that is not a plain non-negative safe
// integer, and trailing data. Only then does the typed decoder run. precheck
// sees the parsed tree before the shape check, so a document of the wrong kind
// is refused as that kind rather than as a list of unknown fields.
func decodeStrict(raw []byte, limit int, destination any, precheck func(tree any) error) error {
	if len(raw) == 0 {
		return refuse(RefusalJSONEmpty)
	}
	if len(raw) > limit {
		return refuse(RefusalJSONTooLarge)
	}
	if !utf8.Valid(raw) {
		return refuse(RefusalJSONMalformed)
	}
	tree, err := parseStrictJSONTree(raw)
	if err != nil {
		return err
	}
	if err := precheck(tree); err != nil {
		return err
	}
	if err := checkStrictJSONShape(tree, reflect.TypeOf(destination).Elem(), "$"); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return refuse(RefusalJSONMalformed)
	}
	return nil
}

// parseStrictJSONTree walks the token stream once, refusing duplicate keys
// before any map could silently keep the last one.
func parseStrictJSONTree(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var parseValue func(path string, depth int) (any, error)
	parseValue = func(path string, depth int) (any, error) {
		if depth > maxJSONDepth {
			return nil, refuseSubject(RefusalJSONTooDeep, path)
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, refuse(RefusalJSONMalformed)
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return token, nil
		}
		switch delimiter {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return nil, refuse(RefusalJSONMalformed)
				}
				if _, seen := object[key]; seen {
					return nil, refuseSubject(RefusalJSONDuplicateKey, path+"."+key)
				}
				child, err := parseValue(path+"."+key, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
				return nil, refuse(RefusalJSONMalformed)
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				child, err := parseValue(fmt.Sprintf("%s[%d]", path, len(array)), depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
				return nil, refuse(RefusalJSONMalformed)
			}
			return array, nil
		}
		return nil, refuse(RefusalJSONMalformed)
	}
	tree, err := parseValue("$", 1)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, refuse(RefusalJSONTrailingData)
	}
	return tree, nil
}

// checkStrictJSONShape requires the parsed tree to have exactly the shape of
// the destination type: the exact key set of every struct, spelled exactly as
// tagged, and the exact JSON type of every leaf.
func checkStrictJSONShape(value any, typeOf reflect.Type, path string) error {
	if value == nil {
		return refuseSubject(RefusalJSONNull, path)
	}
	switch typeOf.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return refuseSubject(RefusalJSONWrongType, path)
		}
		fields := map[string]reflect.Type{}
		order := []string{}
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			fields[name] = field.Type
			order = append(order, name)
		}
		for name := range object {
			if _, known := fields[name]; !known {
				return refuseSubject(RefusalJSONUnknownField, path+"."+name)
			}
		}
		for _, name := range order {
			child, present := object[name]
			if !present {
				return refuseSubject(RefusalJSONMissingField, path+"."+name)
			}
			if err := checkStrictJSONShape(child, fields[name], path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return refuseSubject(RefusalJSONWrongType, path)
		}
		for index, child := range array {
			if err := checkStrictJSONShape(child, typeOf.Elem(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return refuseSubject(RefusalJSONWrongType, path)
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return refuseSubject(RefusalJSONWrongType, path)
		}
	case reflect.Uint32, reflect.Uint64:
		number, ok := value.(json.Number)
		if !ok {
			return refuseSubject(RefusalJSONWrongType, path)
		}
		limit := MaxSafeInteger
		if typeOf.Kind() == reflect.Uint32 {
			limit = uint64(^uint32(0))
		}
		parsed, err := strconv.ParseUint(number.String(), 10, 64)
		if !safeIntegerPattern.MatchString(number.String()) || err != nil || parsed > limit {
			return refuseSubject(RefusalJSONUnsafeInteger, path)
		}
	default:
		// A new field kind must be given an explicit strict rule here before
		// any document may carry it.
		return refuseSubject(RefusalJSONWrongType, path)
	}
	return nil
}

// peekStrictJSONKind returns the top-level schema and kind without requiring
// the rest of the document to have any particular shape, so that a draft is
// refused as a draft rather than as a list of unknown fields.
func peekStrictJSONKind(tree any) (schema, kind string) {
	object, ok := tree.(map[string]any)
	if !ok {
		return "", ""
	}
	schema, _ = object["schema"].(string)
	kind, _ = object["kind"].(string)
	return schema, kind
}
