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
