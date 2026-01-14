// Package templates manages email templates
package templates

import (
	"html/template"
)

// Parser handles template parsing
type Parser struct {
	funcMap template.FuncMap
}

// NewParser creates a new template parser
func NewParser() (*Parser, error) {
	funcMap := template.FuncMap{
		// Add custom template functions here if needed
		"escape": template.HTMLEscapeString,
	}

	return &Parser{
		funcMap: funcMap,
	}, nil
}

// Parse parses a template string
func (p *Parser) Parse(name, content string) (*template.Template, error) {
	return template.New(name).Funcs(p.funcMap).Parse(content)
}

// ParseFiles parses template files
func (p *Parser) ParseFiles(files ...string) (*template.Template, error) {
	return template.New("").Funcs(p.funcMap).ParseFiles(files...)
}
