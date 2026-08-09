package parsers

import (
	"context"

	"github.com/opscustodian/opscustodian/internal/discovery"
	"github.com/opscustodian/opscustodian/internal/model"
)

type Parser interface {
	Name() string
	Supports(discovery.Artifact) bool
	Parse(context.Context, discovery.Artifact) ([]model.Agent, error)
}
