package ua

// Names of additional header parameters (Part 4, 7.1).
const (
	// AdditionalParameterECDHPolicyUri asks the server for an ephemeral key
	// for an ECC user token policy.
	AdditionalParameterECDHPolicyUri = "ECDHPolicyUri"
	// AdditionalParameterECDHKey carries the server's EphemeralKeyType, or a
	// StatusCode if it cannot provide one.
	AdditionalParameterECDHKey = "ECDHKey"
)

// NewAdditionalHeader returns an AdditionalHeader (an AdditionalParametersType)
// with the parameters. Names are in namespace 0.
func NewAdditionalHeader(params ...KeyValuePair) ExtensionObject {
	return NewExtensionObject(&AdditionalParametersType{Parameters: params})
}

// AdditionalParameter returns the value of a parameter of an AdditionalHeader.
func AdditionalParameter(header ExtensionObject, name string) (Variant, bool) {
	p, ok := header.Value.(*AdditionalParametersType)
	if !ok {
		return Variant{}, false
	}
	for _, kv := range p.Parameters {
		if kv.Key.Name == name && kv.Key.NamespaceIndex == 0 {
			return kv.Value, true
		}
	}
	return Variant{}, false
}
