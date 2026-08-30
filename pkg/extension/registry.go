package extension

// entry holds metadata and factory for a registered extension.
type entry struct {
	name    string
	version string
	factory func() Extension
}

var extensions = make(map[string]entry)

// Register stores an extension factory under the given name.
// Typically called from an init() function in the extension package.
func Register(name string, factory func() Extension) {
	if _, exists := extensions[name]; exists {
		panic("extension: " + name + " already registered")
	}
	inst := factory()
	extensions[name] = entry{
		name:    name,
		version: inst.Version(),
		factory: factory,
	}
}

// Create returns a new extension instance by name.
func Create(name string) (Extension, bool) {
	e, ok := extensions[name]
	if !ok {
		return nil, false
	}
	return e.factory(), true
}

// RegisteredExtension holds the name and version of a registered extension.
type RegisteredExtension struct {
	Name    string
	Version string
}

// ListRegistered returns the name and version of all registered extensions.
func ListRegistered() []RegisteredExtension {
	result := make([]RegisteredExtension, 0, len(extensions))
	for _, e := range extensions {
		result = append(result, RegisteredExtension{Name: e.name, Version: e.version})
	}
	return result
}
