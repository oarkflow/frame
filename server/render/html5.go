package render

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oarkflow/frame/internal/utils"
)

// Delims represents a set of Left and Right delimiters for HTML template rendering.
type Delims struct {
	// Left delimiter, defaults to {{.
	Left string
	// Right delimiter, defaults to }}.
	Right string
}

// HtmlEngine struct
type HtmlEngine struct {
	fileSystem http.FileSystem
	funcmap    map[string]interface{}
	Templates  *template.Template
	left       string
	right      string
	directory  string
	extension  string
	layout     string
	mutex      sync.RWMutex
	loaded     bool
	reload     bool
	debug      bool
}

type HtmlConfig struct {
	Directory string
	Extension string
	// Left delimiter, defaults to {{.
	Left string
	// Right delimiter, defaults to }}.
	Right string
}

// NewHtmlRender returns a HTML render engine for Fiber
func NewHtmlRender(config ...HtmlConfig) *HtmlEngine {
	var cfg HtmlConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.Left == "" {
		cfg.Left = "{{"
	}
	if cfg.Right == "" {
		cfg.Right = "}}"
	}
	if cfg.Directory == "" {
		cfg.Directory = "./"
	}
	if cfg.Extension == "" {
		cfg.Extension = ".html"
	}
	engine := &HtmlEngine{
		left:      cfg.Left,
		right:     cfg.Right,
		directory: cfg.Directory,
		extension: cfg.Extension,
		layout:    "embed",
		funcmap:   make(map[string]interface{}),
	}
	engine.AddFunc(engine.layout, func() error {
		return fmt.Errorf("layout called unexpectedly.")
	})
	return engine
}

// NewFileSystem ...
func NewFileSystem(fs http.FileSystem, extension string) *HtmlEngine {
	engine := &HtmlEngine{
		left:       "{{",
		right:      "}}",
		directory:  "/",
		fileSystem: fs,
		extension:  extension,
		layout:     "embed",
		funcmap:    make(map[string]interface{}),
	}
	engine.AddFunc(engine.layout, func() error {
		return fmt.Errorf("layout called unexpectedly.")
	})
	return engine
}

// Layout defines the variable name that will incapsulate the template
func (e *HtmlEngine) Layout(key string) *HtmlEngine {
	e.layout = key
	return e
}

// Delims sets the action delimiters to the specified strings, to be used in
// templates. An empty delimiter stands for the
// corresponding default: {{ or }}.
func (e *HtmlEngine) Delims(left, right string) *HtmlEngine {
	e.left, e.right = left, right
	return e
}

// AddFunc adds the function to the template's function map.
// It is legal to overwrite elements of the default actions
func (e *HtmlEngine) AddFunc(name string, fn interface{}) *HtmlEngine {
	e.mutex.Lock()
	e.funcmap[name] = fn
	e.mutex.Unlock()
	return e
}

// AddFuncMap adds the functions from a map to the template's function map.
// It is legal to overwrite elements of the default actions
func (e *HtmlEngine) AddFuncMap(m map[string]interface{}) *HtmlEngine {
	e.mutex.Lock()
	for name, fn := range m {
		e.funcmap[name] = fn
	}
	e.mutex.Unlock()
	return e
}

// Reload if set to true the templates are reloading on each render,
// use it when you're in development, and you don't want to restart
// the application when you edit a template file.
func (e *HtmlEngine) Reload(enabled bool) *HtmlEngine {
	e.reload = enabled
	return e
}

func (e *HtmlEngine) Close() error {
	return nil
}

// Debug will print the parsed templates when Load is triggered.
func (e *HtmlEngine) Debug(enabled bool) *HtmlEngine {
	e.debug = enabled
	return e
}

// Parse is deprecated, please use Load() instead
func (e *HtmlEngine) Parse() error {
	fmt.Println("Parse() is deprecated, please use Load() instead.")
	return e.Load()
}

// Load parses the templates to the engine.
func (e *HtmlEngine) Load() error {
	if e.loaded {
		return nil
	}
	// race safe
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.Templates = template.New(e.directory)

	// Set template settings
	e.Templates.Delims(e.left, e.right)
	e.Templates.Funcs(e.funcmap)

	walkFn := func(path string, info os.FileInfo, err error) error {
		// Return error if exist
		if err != nil {
			return err
		}
		// Skip file if it's a directory or has no file info
		if info == nil || info.IsDir() {
			return nil
		}
		// Skip file if it does not equal the given template extension
		if len(e.extension) >= len(path) || path[len(path)-len(e.extension):] != e.extension {
			return nil
		}
		// Get the relative file path
		// ./views/html/index.tmpl -> index.tmpl
		rel, err := filepath.Rel(e.directory, path)
		if err != nil {
			return err
		}
		// Reverse slashes '\' -> '/' and
		// partials\footer.tmpl -> partials/footer.tmpl
		name := filepath.ToSlash(rel)
		// Remove ext from name 'index.tmpl' -> 'index'
		name = strings.TrimSuffix(name, e.extension)
		// name = strings.Replace(name, e.extension, "", -1)
		// Read the file
		// #gosec G304
		buf, err := utils.ReadFile(path, e.fileSystem)
		if err != nil {
			return err
		}
		// Create new template associated with the current one
		// This enables use to invoke other templates {{ template .. }}
		_, err = e.Templates.New(name).Parse(string(buf))
		if err != nil {
			return err
		}
		// Debugging
		if e.debug {
			fmt.Printf("views: parsed template: %s\n", name)
		}
		return err
	}
	// notify engine that we parsed all templates
	e.loaded = true
	if e.fileSystem != nil {
		return utils.Walk(e.fileSystem, e.directory, walkFn)
	}
	return filepath.Walk(e.directory, walkFn)
}

// Render will execute the template name along with the given values.
func (e *HtmlEngine) Render(out io.Writer, template string, binding interface{}, layout ...string) error {
	if !e.loaded || e.reload {
		if e.reload {
			e.loaded = false
		}
		if err := e.Load(); err != nil {
			return err
		}
	}

	tmpl := e.Templates.Lookup(template)
	if tmpl == nil {
		return fmt.Errorf("render: template %s does not exist", template)
	}
	if len(layout) > 0 && layout[0] != "" {
		lay := e.Templates.Lookup(layout[0])
		if lay == nil {
			return fmt.Errorf("render: layout %s does not exist", layout[0])
		}
		e.mutex.Lock()
		defer e.mutex.Unlock()
		lay.Funcs(map[string]interface{}{
			e.layout: func() error {
				return tmpl.Execute(out, binding)
			},
		})
		return lay.Execute(out, binding)
	}
	return tmpl.Execute(out, binding)
}
