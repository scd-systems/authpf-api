package main

// scan.go builds the map of who touches the anchorsDB and who holds the lock.
//
// The anchorsDB is a plain map (internal/authpf/anchordb.go) protected by a
// mutex that lives outside it (internal/server/types.go), so safety cannot be
// read from the DB type. It has to be read from every function that reaches the
// map, which is what this file collects.
//
// Names are never hardcoded. The lock and the DB are found by their declared
// type, so renaming lock to dbMu, or moving it into a struct, keeps working:
//
//	lock  -> a package var or struct field of type *sync.Mutex / sync.Mutex
//	db    -> a package var or struct field of type *authpf.AnchorsDB
//
// A function "holds the lock" when it takes that mutex and releases it, with
// defer or with an Unlock that comes after the Lock call.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Func is one function or method, and what its body does with the DB.
type Func struct {
	File     string   // path relative to the code root
	Pkg      string   // Go package clause
	Name     string   // "Func", or "Type.Method" for methods
	Recv     string   // receiver type name, empty for plain functions
	HasLock  bool     // body takes the shared mutex and releases it
	Accesses []string // how the body reaches the map, as source text
	Callees  []string // function and method names the body calls
	Path     []string // call chain from the documented lock holder, filled by the check
	Line     int
}

// Key identifies a function in the ledger and stays stable across runs.
func (f *Func) Key() string { return f.File + "::" + f.Name }

func (f *Func) String() string { return fmt.Sprintf("%s line %d", f.Key(), f.Line) }

// Model is a scanned code root.
type Model struct {
	fset      *token.FileSet
	lockNames map[string]bool // names bound to the shared mutex
	dbNames   map[string]bool // names bound to the DB
	mapFields map[string]bool // field names holding the map inside AnchorsDB
	storeType string          // name of the type that owns the map, as declared
	storeLock bool            // that type declares a mutex of its own
	funcs     []*Func         // every function that reaches the DB map
	byKey     map[string]*Func
	byName    map[string][]*Func // indexed by bare name, what a call site records
}

func newModel() *Model {
	return &Model{
		fset:      token.NewFileSet(),
		lockNames: map[string]bool{},
		dbNames:   map[string]bool{},
		mapFields: map[string]bool{},
		byKey:     map[string]*Func{},
		byName:    map[string][]*Func{},
	}
}

type parsedFile struct {
	rel  string
	file *ast.File
}

// scan parses subdirs below root and reports paths relative to root, which is
// what the ledger keys use. Test files are out of scope on purpose: a test may
// build an unsafe state, that is the whole point of a test.
func scan(root string, subdirs ...string) (*Model, error) {
	m := newModel()
	var parsed []parsedFile

	if len(subdirs) == 0 {
		subdirs = []string{"."}
	}
	for _, sub := range subdirs {
		abs, err := filepath.Abs(filepath.Join(root, sub))
		if err != nil {
			return nil, err
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		err = filepath.Walk(abs, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(m.fset, p, nil, 0)
			if perr != nil {
				return fmt.Errorf("%s: %w", p, perr)
			}
			rel, rerr := filepath.Rel(absRoot, p)
			if rerr != nil {
				rel = p
			}
			parsed = append(parsed, parsedFile{rel: filepath.ToSlash(rel), file: f})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sort.Slice(parsed, func(i, j int) bool {
		if parsed[i].rel != parsed[j].rel {
			return parsed[i].rel < parsed[j].rel
		}
		return false
	})

	// Two passes: the mutex and the DB are usually declared in another file than
	// the functions that use them, so the names have to be known up front.
	for _, pf := range parsed {
		m.indexDecls(pf.file)
	}
	for _, pf := range parsed {
		m.collectFuncs(pf.rel, pf.file)
	}
	sort.Slice(m.funcs, func(i, j int) bool {
		if m.funcs[i].File != m.funcs[j].File {
			return m.funcs[i].File < m.funcs[j].File
		}
		return m.funcs[i].Name < m.funcs[j].Name
	})
	return m, nil
}

// indexDecls records which names are the mutex and which are the DB.
func (m *Model) indexDecls(f *ast.File) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		switch gd.Tok.String() {
		case "var":
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, n := range vs.Names {
					if vs.Type != nil && isLockType(vs.Type) || isLockLit(vs.Values) {
						m.lockNames[n.Name] = true
					}
					if vs.Type != nil && isDBType(vs.Type) {
						m.dbNames[n.Name] = true
					}
				}
			}
		case "type":
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if ts.Name.Name == "AnchorsDB" {
					m.indexAnchorsDB(ts)
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, fld := range st.Fields.List {
					for _, n := range fld.Names {
						if isLockType(fld.Type) {
							m.lockNames[n.Name] = true
						}
						if isDBType(fld.Type) {
							m.dbNames[n.Name] = true
						}
					}
				}
			}
		}
	}
}

func isLockType(e ast.Expr) bool {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "sync" && (sel.Sel.Name == "Mutex" || sel.Sel.Name == "RWMutex")
}

func isLockLit(values []ast.Expr) bool {
	for _, v := range values {
		u, ok := v.(*ast.UnaryExpr)
		if !ok || u.Op.String() != "&" {
			continue
		}
		lit, ok := u.X.(*ast.CompositeLit)
		if ok && isLockType(lit.Type) {
			return true
		}
	}
	return false
}

func isDBType(e ast.Expr) bool {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "AnchorsDB"
}

// AnchorsDB used to be a plain map, which is why safety had to be read off every
// caller. It is a struct now and the map moved inside it, so the guard has to read
// the type itself as well:
//
//	AnchorsDB struct  -> its mutex field is a lock, its map field is the DB
//
// Without this, a.mu.Lock() could be deleted from AnchorsDB.Add and nothing here
// would notice: anchordb.go has no `x.AnchorsDB` selector left to match, so the
// file stops being scanned at all and the guard greens out over the one thing it
// exists to watch.
func (m *Model) indexAnchorsDB(ts *ast.TypeSpec) {
	st, ok := ts.Type.(*ast.StructType)
	if !ok {
		return
	}
	m.storeType = ts.Name.Name
	for _, fld := range st.Fields.List {
		if len(fld.Names) == 0 {
			continue
		}
		if isLockType(fld.Type) {
			m.lockNames[fld.Names[0].Name] = true
			m.storeLock = true
		}
		if isDBMapType(fld.Type) {
			m.mapFields[fld.Names[0].Name] = true
		}
	}
}

// isDBMapType matches the `map[string]*authpf.AuthPFAnchor` field inside AnchorsDB.
// The element type is named rather than inferred, so a rename of the anchor type is
// a finding here instead of a silent loss of coverage.
func isDBMapType(e ast.Expr) bool {
	mp, ok := e.(*ast.MapType)
	if !ok {
		return false
	}
	star, ok := mp.Value.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch t := star.X.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name == "AuthPFAnchor"
	case *ast.Ident: // declared in the same package, as the selftest fixture has it
		return t.Name == "AuthPFAnchor"
	}
	return false
}

func funcRecv(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	return recvName(fd.Recv.List[0].Type)
}
