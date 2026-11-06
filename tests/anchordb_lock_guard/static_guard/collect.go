package main

// collect.go walks one function body at a time and answers two questions about
// it: does it reach the DB map, and does it hold the lock while doing so.
//
// Six source forms count as reaching the map. All six were confirmed against the
// real code, not guessed:
//
//	range *e.db                  iterate every entry        exec.go, scheduler.go
//	*h.db                        read the map as a value    handler.go
//	(*h.db)[user]                index read or write        handler.go
//	len(*e.db)                   read the count             exec.go, shutdown.go
//	h.db.Add(r) / .Remove / ...  mutate through a DB field  api, exec, scheduler
//	clear(a.data)                empty the map in place     anchordb.go Flush
//
// Holding the lock means the body calls Lock on the mutex and releases it with
// defer, or with an Unlock that comes after the Lock. A Lock with no Unlock is
// not counted as protection: a mutex nobody releases is worse than none at all.

import (
	"fmt"
	"go/ast"
	"go/printer"
	"strings"
)

// lockRef reports whether e names the shared mutex, whether it is the package
// level `lock` or a field reached as `h.lock` / `s.lock`.
func (m *Model) lockRef(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return m.lockNames[t.Name]
	case *ast.SelectorExpr:
		return m.lockNames[t.Sel.Name]
	case *ast.ParenExpr:
		return m.lockRef(t.X)
	}
	return false
}

// dbRef reports whether e names the DB: the package var `db`, a field such as
// `h.db`, or either of those behind a deref or parentheses.
func (m *Model) dbRef(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return m.dbNames[t.Name]
	case *ast.SelectorExpr:
		return m.dbNames[t.Sel.Name] || m.mapFields[t.Sel.Name]
	case *ast.StarExpr:
		return m.dbRef(t.X)
	case *ast.ParenExpr:
		return m.dbRef(t.X)
	}
	return false
}

func (m *Model) collectFuncs(rel string, f *ast.File) {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		fn := &Func{
			File: rel,
			Pkg:  f.Name.Name,
			Name: funcName(fd),
			Recv: funcRecv(fd),
			Line: m.fset.Position(fd.Pos()).Line,
		}
		m.walkBody(fn, fd.Body)
		// Every function is indexed, not only the ones that touch the DB: the
		// ledger names lock holders such as Scheduler.Run, which reach the map
		// through a helper and have no DB expression of their own, and the call
		// path check has to walk through plain functions too.
		if len(fn.Accesses) > 0 {
			m.funcs = append(m.funcs, fn)
		}
		// Every function is indexed, not only the accessors: the ledger names lock
		// holders that reach the map through a helper, and the call path has to be
		// able to walk through plain functions on the way.
		m.byKey[fn.Key()] = fn
		m.byName[shortName(fn.Name)] = append(m.byName[shortName(fn.Name)], fn)
	}
}

func (m *Model) walkBody(fn *Func, body *ast.BlockStmt) {
	lockAt, unlockAt := -1, -1
	deferUnlock := false
	step := 0

	ast.Inspect(body, func(n ast.Node) bool {
		step++
		switch e := n.(type) {
		case *ast.DeferStmt:
			sel, ok := e.Call.Fun.(*ast.SelectorExpr)
			if ok && m.lockRef(sel.X) && isUnlock(sel.Sel.Name) {
				deferUnlock = true
			}

		case *ast.CallExpr:
			// len(db) is the one plain function call that reads the map.
			if id, ok := e.Fun.(*ast.Ident); ok {
				fn.Callees = append(fn.Callees, id.Name)
				if (id.Name == "len" || id.Name == "clear") && len(e.Args) == 1 && m.dbRef(e.Args[0]) {
					fn.add(fmt.Sprintf("%s(%s)", id.Name, m.expr(e.Args[0])))
				}
				return true
			}
			sel, ok := e.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch {
			case m.lockRef(sel.X) && isLockCall(sel.Sel.Name):
				if lockAt < 0 {
					lockAt = step
				}
			case m.lockRef(sel.X) && isUnlock(sel.Sel.Name):
				unlockAt = step
			}
			// A method call on a DB field writes or reads the map inside. It is a
			// DB access, not a hop in the call graph: those methods are the map
			// primitives and are never a step toward a helper that needs a holder.
			if m.dbRef(sel.X) {
				fn.add(m.expr(sel))
				return true
			}
			fn.Callees = append(fn.Callees, sel.Sel.Name)

		case *ast.RangeStmt:
			if e.X != nil && m.dbRef(e.X) {
				fn.add(fmt.Sprintf("range %s", m.expr(e.X)))
			}

		case *ast.StarExpr:
			if m.dbRef(e.X) {
				fn.add(fmt.Sprintf("*%s", m.expr(e.X)))
			}

		case *ast.IndexExpr:
			if m.dbRef(e.X) {
				fn.add(fmt.Sprintf("index %s", m.expr(e.X)))
			}

		case *ast.UnaryExpr:
			if m.dbRef(e.X) {
				fn.add(fmt.Sprintf("deref %s", m.expr(e.X)))
			}

		case *ast.AssignStmt:
			// *a = make(AnchorsDB) replaces the whole map. That is a write, and
			// Flush() in anchordb.go does exactly this.
			for _, lhs := range e.Lhs {
				if star, ok := lhs.(*ast.StarExpr); ok && m.dbRef(star.X) {
					fn.add(fmt.Sprintf("assign *%s", m.expr(star.X)))
				}
			}
		}
		return true
	})

	fn.HasLock = lockAt >= 0 && (deferUnlock || unlockAt >= lockAt)
}

func (f *Func) add(text string) {
	for _, seen := range f.Accesses {
		if seen == text {
			return
		}
	}
	f.Accesses = append(f.Accesses, text)
}

func (m *Model) expr(e ast.Expr) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, m.fset, e); err != nil {
		return "<expr>"
	}
	return sb.String()
}

func isLockCall(name string) bool { return name == "Lock" || name == "RLock" }

func isUnlock(name string) bool { return name == "Unlock" || name == "RUnlock" }

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return recvName(fd.Recv.List[0].Type) + "." + fd.Name.Name
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvName(t.X)
	case *ast.IndexListExpr:
		return recvName(t.X)
	}
	return "?"
}
