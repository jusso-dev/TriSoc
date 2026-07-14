package aws

import (
	"context"
	"time"
)

type Collector struct {
	api   API
	clock func() time.Time
}

func NewCollector(api API) *Collector {
	return &Collector{api: api, clock: func() time.Time { return time.Now().UTC() }}
}
func (c *Collector) Discover(ctx context.Context, target Target) (Snapshot, error) {
	snapshot, err := c.api.Discover(ctx, target)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.ObservedAt = c.clock()
	return snapshot, nil
}
