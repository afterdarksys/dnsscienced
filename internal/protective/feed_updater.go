package protective

import (
	"fmt"
	"log"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/experimental"
)

// FeedUpdater manages automatic blocklist feed updates
type FeedUpdater struct {
	engine *Engine
	config experimental.ProtectiveDNSConfig
	stopCh chan struct{}
}

// NewFeedUpdater creates a new feed updater
func NewFeedUpdater(engine *Engine, config experimental.ProtectiveDNSConfig) *FeedUpdater {
	return &FeedUpdater{
		engine: engine,
		config: config,
		stopCh: make(chan struct{}),
	}
}

// Run starts the feed updater loop
func (f *FeedUpdater) Run() {
	// Initial update
	if err := f.updateAllFeeds(); err != nil {
		log.Printf("Protective DNS: initial feed update failed: %v", err)
	}

	// Schedule periodic updates
	ticker := time.NewTicker(f.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := f.updateAllFeeds(); err != nil {
				log.Printf("Protective DNS: feed update failed: %v", err)
			}

		case <-f.stopCh:
			return
		}
	}
}

// Stop stops the feed updater
func (f *FeedUpdater) Stop() {
	close(f.stopCh)
}

// updateAllFeeds updates all configured feeds
func (f *FeedUpdater) updateAllFeeds() error {
	log.Printf("Protective DNS: updating %d feeds...", len(f.config.BlocklistFeeds))

	successCount := 0
	for _, feed := range f.config.BlocklistFeeds {
		if !feed.Enabled {
			continue
		}

		// Use feed-specific interval if set, otherwise use global
		// Note: Interval checking logic would go here in production
		// This would check Last-Modified headers, ETags, etc.
		_ = f.config.UpdateInterval
		if feed.Interval > 0 {
			// Feed-specific interval
			_ = feed.Interval
		}

		if err := f.updateFeed(feed); err != nil {
			log.Printf("Protective DNS: failed to update feed %s: %v", feed.Name, err)
			continue
		}

		successCount++
	}

	log.Printf("Protective DNS: updated %d/%d feeds successfully", successCount, len(f.config.BlocklistFeeds))
	return nil
}

// updateFeed updates a single feed
func (f *FeedUpdater) updateFeed(feed experimental.Feed) error {
	log.Printf("Protective DNS: updating feed %s from %s", feed.Name, feed.URL)

	// Determine feed format
	format := feed.Format
	if format == "" {
		// Auto-detect format from URL or content
		format = "domains"
	}

	// Filter by enabled categories
	if !f.isCategoryEnabled(feed.Category) {
		log.Printf("Protective DNS: skipping feed %s (category %s not enabled)", feed.Name, feed.Category)
		return nil
	}

	// Clear existing entries from this source
	source := feed.Name
	f.engine.blocklist.ClearSource(source)

	// Load new entries
	err := f.engine.blocklist.LoadFromURL(
		feed.URL,
		feed.Category,
		source,
		format,
		feed.APIKey,
		feed.Headers,
	)

	if err != nil {
		return fmt.Errorf("load feed: %w", err)
	}

	log.Printf("Protective DNS: feed %s updated successfully", feed.Name)
	return nil
}

// isCategoryEnabled checks if a category is enabled
func (f *FeedUpdater) isCategoryEnabled(category string) bool {
	if len(f.config.Categories) == 0 {
		return true // No category filter, all enabled
	}

	for _, cat := range f.config.Categories {
		if cat == category {
			return true
		}
	}

	return false
}
