package extension

var extensions = make(map[string]func() Extension)

// Register stores an extension factory under the given name.
// Typically called from an init() function in the extension package.
func Register(name string, factory func() Extension) {
	if _, exists := extensions[name]; exists {
		panic("extension: " + name + " already registered")
	}
	extensions[name] = factory
}

// Get returns an extension instance by name.
func Get(name string) (Extension, bool) {
	f, ok := extensions[name]
	if !ok {
		return nil, false
	}
	return f(), true
}

// RegisteredExtension holds the name and version of a registered extension.
type RegisteredExtension struct {
	Name    string
	Version string
}

// ListRegistered returns the name and version of all registered extensions.
func ListRegistered() []RegisteredExtension {
	result := make([]RegisteredExtension, 0, len(extensions))
	for name, factory := range extensions {
		inst := factory()
		result = append(result, RegisteredExtension{Name: name, Version: inst.Version()})
	}
	return result
}
