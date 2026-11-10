// Module bench compares uastack with gopcua. It is a separate module so
// that the uastack module itself does not depend on gopcua.
module github.com/bamchoh/uastack/bench

go 1.25.6

replace github.com/bamchoh/uastack => ../

require (
	github.com/bamchoh/uastack v0.0.0-00010101000000-000000000000
	github.com/gopcua/opcua v0.9.1
)

require github.com/google/uuid v1.6.0 // indirect
