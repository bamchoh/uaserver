// Module bench compares uaserver with gopcua. It is a separate module so
// that the uaserver module itself does not depend on gopcua.
module github.com/bamchoh/uaserver/bench

go 1.25.6

replace github.com/bamchoh/uaserver => ../

require (
	github.com/bamchoh/uaserver v0.0.0-00010101000000-000000000000
	github.com/gopcua/opcua v0.9.1
)

require github.com/google/uuid v1.6.0 // indirect
