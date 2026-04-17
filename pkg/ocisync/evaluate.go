package ocisync

import "context"

// Evaluator defines the interface for checks that determine whether a SyncCandidate should be processed.
type Evaluator interface {
	Name() string
	Check(ctx context.Context, candidate SyncCandidate) error
}
