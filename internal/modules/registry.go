package modules

import "sync"

// Registry holds references to all module status trackers in the system.
// Components register themselves at startup; the dashboard reads the registry.
type Registry struct {
	mu       sync.RWMutex
	trackers map[ModuleID]*StatusTracker
}

func NewRegistry() *Registry {
	return &Registry{
		trackers: make(map[ModuleID]*StatusTracker),
	}
}

func (r *Registry) Register(tracker *StatusTracker) {
	r.mu.Lock()
	r.trackers[tracker.id] = tracker
	r.mu.Unlock()
}

// AllStatuses returns a snapshot of every registered module's status.
func (r *Registry) AllStatuses() map[string]ModuleStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]ModuleStatus, len(r.trackers))
	for id, tracker := range r.trackers {
		result[string(id)] = tracker.Status()
	}
	return result
}

// StatusesByCategory returns statuses grouped by category.
func (r *Registry) StatusesByCategory() map[string][]ModuleStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string][]ModuleStatus)
	for _, tracker := range r.trackers {
		s := tracker.Status()
		result[s.Category] = append(result[s.Category], s)
	}
	return result
}
