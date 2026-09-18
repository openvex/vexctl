/*
Copyright 2026 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package validate

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

// The field names that more than one OpenVEX struct shares.
const (
	fieldContext    = "@context"
	fieldID         = "@id"
	fieldSupplier   = "supplier"
	fieldTimestamp  = "timestamp"
	fieldVersion    = "version"
	fieldStatements = "statements"
)

// fieldType is the JSON shape a known OpenVEX field holds.
type fieldType int

const (
	typeString fieldType = iota
	typeInteger
	typeTimestamp
	typeStringList
	typeStringMap
	typeObject
	typeObjectList
)

// field describes one field of an OpenVEX struct.
type field struct {
	// name is the field name as it appears in the JSON document.
	name string

	// kind is the shape the field's value must have.
	kind fieldType

	// required marks fields the spec lists as mandatory.
	required bool

	// schema describes the fields of an object, or of the objects in a list.
	schema []field

	// note, when set, is warned about even though the field is accepted. It
	// covers fields the spec and vexctl disagree on.
	note string
}

// The OpenVEX structs, in the order the spec lists their fields. Walking them
// in a fixed order keeps the findings of a run stable.
var (
	// vulnerabilityFields is the struct naming the vulnerability a statement
	// is about.
	vulnerabilityFields = []field{
		{name: fieldID, kind: typeString},
		{name: "name", kind: typeString, required: true},
		{name: "description", kind: typeString},
		{name: "aliases", kind: typeStringList},
	}

	// subcomponentFields is the component struct, which cannot nest further
	// components.
	subcomponentFields = []field{
		{name: fieldID, kind: typeString},
		{name: "identifiers", kind: typeStringMap},
		{name: "hashes", kind: typeStringMap},
		{name: fieldSupplier, kind: typeString},
	}

	// productFields is a component that also carries the subcomponents the
	// statement is about.
	productFields = append(
		slices.Clone(subcomponentFields),
		field{name: "subcomponents", kind: typeObjectList, schema: subcomponentFields},
	)

	// statementFields is the assertion the document's author makes.
	statementFields = []field{
		{name: fieldID, kind: typeString},
		{
			name: fieldVersion, kind: typeInteger,
			note: "the statement version field is defined by the OpenVEX spec but vexctl does not read it; it is dropped when the document is rewritten",
		},
		{name: "vulnerability", kind: typeObject, required: true, schema: vulnerabilityFields},
		{name: fieldTimestamp, kind: typeTimestamp},
		{name: "last_updated", kind: typeTimestamp},
		{name: "products", kind: typeObjectList, schema: productFields},
		{name: "status", kind: typeString, required: true},
		{
			name: fieldSupplier, kind: typeString,
			note: "the statement supplier field is defined by the OpenVEX spec but vexctl does not read it; it is dropped when the document is rewritten",
		},
		{name: "status_notes", kind: typeString},
		{name: "justification", kind: typeString},
		{name: "impact_statement", kind: typeString},
		{name: "action_statement", kind: typeString},
		{name: "action_statement_timestamp", kind: typeTimestamp},
	}

	// documentFields is the OpenVEX document itself. @context is not marked
	// required here because checkContext reports on it before this runs.
	documentFields = []field{
		{name: fieldContext, kind: typeString},
		{name: fieldID, kind: typeString, required: true},
		{name: "author", kind: typeString, required: true},
		{name: "role", kind: typeString},
		{name: fieldTimestamp, kind: typeTimestamp, required: true},
		{name: "last_updated", kind: typeTimestamp},
		{name: fieldVersion, kind: typeInteger, required: true},
		{name: "tooling", kind: typeString},
		{
			name: fieldSupplier, kind: typeString,
			note: "supplier was removed from the OpenVEX document struct; it belongs on the statement or on its components",
		},
		{name: fieldStatements, kind: typeObjectList, required: true, schema: statementFields},
	}
)

// checkSchema walks the document checking that every field is one the OpenVEX
// spec defines and that it holds a value of the expected shape. Unknown fields
// matter because vexctl drops them without a word, which is how a typo in a
// hand edited document turns into silently missing data.
func (r *Result) checkSchema(raw map[string]any) {
	r.checkObject(raw, documentFields, "")
}

func (r *Result) checkObject(obj map[string]any, schema []field, path string) {
	for i := range schema {
		f := &schema[i]
		fieldPath := join(path, f.name)

		value, found := obj[f.name]
		if !found || value == nil {
			if f.required {
				r.errorf(CheckRequired, fieldPath, "required field %q is missing", f.name)
			}
			continue
		}

		if f.note != "" {
			r.warnf(CheckDroppedField, fieldPath, "%s", f.note)
		}

		r.checkFieldValue(value, f, fieldPath)
	}

	for _, name := range slices.Sorted(maps.Keys(obj)) {
		if knownField(schema, name) {
			continue
		}
		r.warnf(
			CheckUnknownField, join(path, name),
			"%q is not an OpenVEX v%s field and is ignored when the document is read",
			name, vex.SpecVersion,
		)
	}
}

// checkFieldValue checks one field's value against the shape its schema
// declares. f is a pointer only to keep the struct from being copied.
func (r *Result) checkFieldValue(value any, f *field, path string) {
	switch f.kind {
	case typeString:
		text, ok := value.(string)
		if !ok {
			r.typeErrorf(path, "a string", value)
			return
		}
		if f.required && text == "" {
			r.errorf(CheckRequired, path, "required field %q is empty", f.name)
		}

	case typeInteger:
		number, ok := value.(json.Number)
		if !ok {
			r.typeErrorf(path, "a whole number", value)
			return
		}
		if _, err := number.Int64(); err != nil {
			r.errorf(CheckFieldType, path, "%s is not a whole number", number)
		}

	case typeTimestamp:
		text, ok := value.(string)
		if !ok {
			r.typeErrorf(path, "an RFC3339 timestamp", value)
			return
		}
		if _, err := time.Parse(time.RFC3339, text); err != nil {
			r.errorf(CheckFieldType, path, "%q is not an RFC3339 timestamp, dates look like %q", text, "2024-05-17T09:30:00Z")
		}

	case typeStringList:
		items, ok := value.([]any)
		if !ok {
			r.typeErrorf(path, "a list", value)
			return
		}
		for i, item := range items {
			if _, ok := item.(string); !ok {
				r.typeErrorf(fmt.Sprintf("%s[%d]", path, i), "a string", item)
			}
		}

	case typeStringMap:
		entries, ok := value.(map[string]any)
		if !ok {
			r.typeErrorf(path, "an object", value)
			return
		}
		for _, key := range slices.Sorted(maps.Keys(entries)) {
			if _, ok := entries[key].(string); !ok {
				r.typeErrorf(join(path, key), "a string", entries[key])
			}
		}

	case typeObject:
		entries, ok := value.(map[string]any)
		if !ok {
			r.typeErrorf(path, "an object", value)
			return
		}
		r.checkObject(entries, f.schema, path)

	case typeObjectList:
		items, ok := value.([]any)
		if !ok {
			r.typeErrorf(path, "a list", value)
			return
		}
		for i, item := range items {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			entries, ok := item.(map[string]any)
			if !ok {
				r.typeErrorf(itemPath, "an object", item)
				continue
			}
			r.checkObject(entries, f.schema, itemPath)
		}
	}
}

func (r *Result) typeErrorf(path, want string, got any) {
	r.errorf(CheckFieldType, path, "expected %s, found %s", want, jsonTypeName(got))
}

func knownField(schema []field, name string) bool {
	for i := range schema {
		if schema[i].name == name {
			return true
		}
	}
	return false
}

// join builds the dotted path of a field inside its parent.
func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// jsonTypeName names the JSON type of a decoded value for an error message.
func jsonTypeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case json.Number:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "a list"
	case map[string]any:
		return "an object"
	default:
		return "an unrecognized value"
	}
}
