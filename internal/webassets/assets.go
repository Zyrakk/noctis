package webassets

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

func FS() fs.FS {
	f, e := fs.Sub(files, "static")
	if e != nil {
		panic(e)
	}
	return f
}
