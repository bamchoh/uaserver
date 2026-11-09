package memstat

// The address space used by both benchmark servers.
const (
	NamespaceURI = "urn:bench"
	NumVars      = 1000 // Int32 variables "v0" .. "v999" with string node ids
	FolderID     = 85   // numeric id (in the bench namespace) of the folder holding the variables
)
