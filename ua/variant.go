package ua

import (
	"fmt"
	"reflect"
	"time"
)

// Variant is a union of all built-in types, as scalars or arrays.
//
// Scalars are held as their Go type (bool, int8, byte, int16, uint16, int32,
// uint32, int64, uint64, float32, float64, string, time.Time, Guid, []byte
// (ByteString), XmlElement, NodeId, ExpandedNodeId, StatusCode, QualifiedName,
// LocalizedText, ExtensionObject, DataValue, *DiagnosticInfo). Arrays are held
// as slices of these types (a Byte array is a []byte with IsArray() true).
// Multi-dimensional arrays are stored flattened together with Dimensions().
type Variant struct {
	typ     TypeID
	isArray bool
	dims    []int32
	value   any
}

// NewVariant creates a Variant from a Go value. It panics if the value type is not supported.
func NewVariant(v any) Variant {
	vr, err := TryVariant(v)
	if err != nil {
		panic(err)
	}
	return vr
}

// TryVariant creates a Variant from a Go value.
func TryVariant(v any) (Variant, error) {
	switch x := v.(type) {
	case nil:
		return Variant{}, nil
	case Variant:
		return x, nil
	case bool:
		return Variant{typ: TypeBoolean, value: x}, nil
	case int8:
		return Variant{typ: TypeSByte, value: x}, nil
	case byte:
		return Variant{typ: TypeByte, value: x}, nil
	case int16:
		return Variant{typ: TypeInt16, value: x}, nil
	case uint16:
		return Variant{typ: TypeUInt16, value: x}, nil
	case int32:
		return Variant{typ: TypeInt32, value: x}, nil
	case uint32:
		return Variant{typ: TypeUInt32, value: x}, nil
	case int64:
		return Variant{typ: TypeInt64, value: x}, nil
	case uint64:
		return Variant{typ: TypeUInt64, value: x}, nil
	case int:
		return Variant{typ: TypeInt64, value: int64(x)}, nil
	case float32:
		return Variant{typ: TypeFloat, value: x}, nil
	case float64:
		return Variant{typ: TypeDouble, value: x}, nil
	case string:
		return Variant{typ: TypeString, value: x}, nil
	case time.Time:
		return Variant{typ: TypeDateTime, value: x}, nil
	case Guid:
		return Variant{typ: TypeGuid, value: x}, nil
	case []byte:
		return Variant{typ: TypeByteString, value: x}, nil
	case XmlElement:
		return Variant{typ: TypeXmlElement, value: x}, nil
	case NodeId:
		return Variant{typ: TypeNodeId, value: x}, nil
	case ExpandedNodeId:
		return Variant{typ: TypeExpandedNodeId, value: x}, nil
	case StatusCode:
		return Variant{typ: TypeStatusCode, value: x}, nil
	case QualifiedName:
		return Variant{typ: TypeQualifiedName, value: x}, nil
	case LocalizedText:
		return Variant{typ: TypeLocalizedText, value: x}, nil
	case ExtensionObject:
		return Variant{typ: TypeExtensionObject, value: x}, nil
	case Structure:
		return Variant{typ: TypeExtensionObject, value: NewExtensionObject(x)}, nil
	case DataValue:
		return Variant{typ: TypeDataValue, value: x}, nil
	case *DiagnosticInfo:
		return Variant{typ: TypeDiagnosticInfo, value: x}, nil

	case []bool:
		return arr(TypeBoolean, x), nil
	case []int8:
		return arr(TypeSByte, x), nil
	case []int16:
		return arr(TypeInt16, x), nil
	case []uint16:
		return arr(TypeUInt16, x), nil
	case []int32:
		return arr(TypeInt32, x), nil
	case []uint32:
		return arr(TypeUInt32, x), nil
	case []int64:
		return arr(TypeInt64, x), nil
	case []uint64:
		return arr(TypeUInt64, x), nil
	case []float32:
		return arr(TypeFloat, x), nil
	case []float64:
		return arr(TypeDouble, x), nil
	case []string:
		return arr(TypeString, x), nil
	case []time.Time:
		return arr(TypeDateTime, x), nil
	case []Guid:
		return arr(TypeGuid, x), nil
	case [][]byte:
		return arr(TypeByteString, x), nil
	case []XmlElement:
		return arr(TypeXmlElement, x), nil
	case []NodeId:
		return arr(TypeNodeId, x), nil
	case []ExpandedNodeId:
		return arr(TypeExpandedNodeId, x), nil
	case []StatusCode:
		return arr(TypeStatusCode, x), nil
	case []QualifiedName:
		return arr(TypeQualifiedName, x), nil
	case []LocalizedText:
		return arr(TypeLocalizedText, x), nil
	case []ExtensionObject:
		return arr(TypeExtensionObject, x), nil
	case []DataValue:
		return arr(TypeDataValue, x), nil
	case []Variant:
		return arr(TypeVariant, x), nil
	case []*DiagnosticInfo:
		return arr(TypeDiagnosticInfo, x), nil
	}
	// Enumerations and slices of structures.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int32:
		return Variant{typ: TypeInt32, value: int32(rv.Int())}, nil
	case reflect.Uint8:
		return Variant{typ: TypeByte, value: byte(rv.Uint())}, nil
	case reflect.Uint16:
		return Variant{typ: TypeUInt16, value: uint16(rv.Uint())}, nil
	case reflect.Uint32:
		return Variant{typ: TypeUInt32, value: uint32(rv.Uint())}, nil
	case reflect.Slice:
		et := rv.Type().Elem()
		n := rv.Len()
		switch {
		case et.Kind() == reflect.Int32:
			a := make([]int32, n)
			for i := range a {
				a[i] = int32(rv.Index(i).Int())
			}
			return arr(TypeInt32, a), nil
		case et.Implements(reflect.TypeOf((*Structure)(nil)).Elem()):
			a := make([]ExtensionObject, n)
			for i := range a {
				a[i] = NewExtensionObject(rv.Index(i).Interface().(Structure))
			}
			return arr(TypeExtensionObject, a), nil
		case reflect.PointerTo(et).Implements(reflect.TypeOf((*Structure)(nil)).Elem()):
			a := make([]ExtensionObject, n)
			for i := range a {
				a[i] = NewExtensionObject(rv.Index(i).Addr().Interface().(Structure))
			}
			return arr(TypeExtensionObject, a), nil
		}
	case reflect.Struct:
		if rv.CanAddr() {
			break
		}
		p := reflect.New(rv.Type())
		p.Elem().Set(rv)
		if s, ok := p.Interface().(Structure); ok {
			return Variant{typ: TypeExtensionObject, value: NewExtensionObject(s)}, nil
		}
	}
	return Variant{}, fmt.Errorf("ua: unsupported variant value type %T", v)
}

func arr(t TypeID, v any) Variant { return Variant{typ: t, isArray: true, value: v} }

// NewByteArrayVariant returns a Variant holding an array of Byte (not a ByteString).
func NewByteArrayVariant(b []byte) Variant { return Variant{typ: TypeByte, isArray: true, value: b} }

// NewMatrixVariant returns a multi-dimensional array Variant. flat must be a slice
// as accepted by NewVariant and its length must equal the product of dims.
func NewMatrixVariant(flat any, dims []int32) (Variant, error) {
	v, err := TryVariant(flat)
	if err != nil {
		return v, err
	}
	if !v.isArray {
		return v, fmt.Errorf("ua: matrix value must be a slice")
	}
	n := int32(1)
	for _, d := range dims {
		n *= d
	}
	if int(n) != v.ArrayLength() {
		return v, fmt.Errorf("ua: matrix dimensions do not match length")
	}
	if len(dims) > 1 {
		v.dims = append([]int32(nil), dims...)
	}
	return v, nil
}

// Type returns the built-in type of the value.
func (v Variant) Type() TypeID { return v.typ }

// IsNull reports whether the variant is empty.
func (v Variant) IsNull() bool { return v.typ == TypeNull }

// IsArray reports whether the variant holds an array.
func (v Variant) IsArray() bool { return v.isArray }

// Value returns the Go value.
func (v Variant) Value() any { return v.value }

// Dimensions returns the array dimensions for multi-dimensional arrays, or
// nil for scalars and one dimensional arrays.
func (v Variant) Dimensions() []int32 { return v.dims }

// ArrayLength returns the number of elements for arrays and -1 for scalars.
func (v Variant) ArrayLength() int {
	if !v.isArray {
		return -1
	}
	return reflect.ValueOf(v.value).Len()
}

// ValueRank returns -1 for scalars, 1 for arrays and n for n-dimensional matrices.
func (v Variant) ValueRank() int32 {
	if !v.isArray {
		return -1
	}
	if len(v.dims) > 1 {
		return int32(len(v.dims))
	}
	return 1
}

func (v Variant) String() string {
	if v.typ == TypeNull {
		return "null"
	}
	return fmt.Sprintf("%v", v.value)
}
