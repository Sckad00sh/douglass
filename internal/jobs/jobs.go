// Package jobs is Douglas's tracker for long-running operations
// (file uploads, preprocessor invocations). The package is intentionally
// minimal: a goroutine-safe map of jobs with cancellation hooks, plus
// a bounded worker pool that pulls from a channel.
//
// Why not just run uploads inline? An MFT upload over loopback is fast
// (~5s for 2 GB), but raw-artifact preprocessing via EZ Tools takes
// 30s+ for big files. Holding an HTTP request open that long is fragile
// (browser refreshes, network blips). The async-job pattern lets the
// front-end fire-and-forget, poll for status, and resume gracefully
// after a page refresh.
//
// For v0.11.0 the worker pool only handles CSV passthrough -- there's
// no subprocess execution yet. The shape is in place so v0.11.1 can
// drop in tool dispatch with no API or state changes.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Status is the lifecycle state of a job. The transitions are:
//
//	queued -> running -> {complete, failed, cancelled}
//
// Once a job is in a terminal state it doesn't move again. The store
// keeps terminal jobs around (capped) so the front-end can display
// recent history.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusComplete  Status = "complete"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Kind describes what the job is doing. Affects how the front-end
// renders its progress card.
type Kind string

const (
	// KindUpload is a CSV passthrough -- file lands directly in the
	// host's artifacts/ folder, no preprocessing.
	KindUpload Kind = "upload"
	// KindPreprocess (v0.11.1+) means a raw artifact will be run
	// through an EZ Tool before landing in artifacts/. Reserved now
	// so the front-end knows about the variant before it's
	// implemented.
	KindPreprocess Kind = "preprocess"
)

// Job is the public view of a job: read-only from the outside, mutated
// only by the store under its lock. JSON-friendly for the /api/jobs
// endpoint.
type Job struct {
	ID         string     `json:"id"`
	Kind       Kind       `json:"kind"`
	Status     Status     `json:"status"`
	HostID     string     `json:"hostId"`
	FileName   string     `json:"fileName"`   // analyst-supplied (sanitized for display)
	ToolName   string     `json:"toolName"`   // empty for upload kind
	Progress   string     `json:"progress"`   // free-form status line (e.g. "uploading 412/842 MB")
	Error      string     `json:"error,omitempty"`
	ResultID   string     `json:"resultId,omitempty"` // artifact ID when complete
	StartedAt  time.Time  `json:"startedAt"`
	EndedAt    *time.Time `json:"endedAt,omitempty"`

	// cancel is the context cancellation for the worker handling this
	// job. Set to non-nil when the job enters running state, used to
	// kill the work mid-flight from Cancel().
	cancel context.CancelFunc
}

// IsTerminal reports whether the job has reached a final state and
// won't change further.
func (j *Job) IsTerminal() bool {
	switch j.Status {
	case StatusComplete, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// Work is the function a job runs. It receives the job's context (for
// cancellation) and the job itself (to update Progress as it goes).
// Return value is the result artifact ID (if any) and an error.
// Errors put the job in StatusFailed with the error string surfaced.
type Work func(ctx context.Context, j *Job) (resultID string, err error)

// Store is the goroutine-safe job tracker plus worker pool. A typical
// Douglas process has exactly one Store, set up at server start.
type Store struct {
	mu      sync.RWMutex
	jobs    map[string]*Job
	pending chan pendingJob
	maxJobs int    // soft cap on retained terminal jobs
	stop    chan struct{}
	stopped bool
}

type pendingJob struct {
	id   string
	work Work
}

// NewStore creates a store with the given worker count. Workers run in
// background goroutines until Close() is called. Caller should pick
// workers based on what the jobs are CPU-bound or I/O-bound -- 2 is a
// good default for an analyst-grade box where the work mixes uploads
// (I/O) and EZ Tools (CPU).
func NewStore(workers int) *Store {
	if workers < 1 {
		workers = 1
	}
	s := &Store{
		jobs:    make(map[string]*Job),
		pending: make(chan pendingJob, 64),
		maxJobs: 200, // retain at most 200 terminal jobs in history
		stop:    make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		go s.worker()
	}
	return s
}

// Close stops the worker pool. In-flight jobs are cancelled via their
// contexts. Safe to call multiple times.
func (s *Store) Close() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	close(s.stop)
	// Cancel everything still running.
	for _, j := range s.jobs {
		if j.cancel != nil && !j.IsTerminal() {
			j.cancel()
		}
	}
	s.mu.Unlock()
}

// Enqueue creates a new job in StatusQueued and schedules the given
// work function. Returns the job (with its assigned ID).
// The work function will be called once a worker is free.
func (s *Store) Enqueue(kind Kind, hostID, fileName, toolName string, work Work) *Job {
	id := newJobID()
	j := &Job{
		ID:        id,
		Kind:      kind,
		Status:    StatusQueued,
		HostID:    hostID,
		FileName:  fileName,
		ToolName:  toolName,
		StartedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	s.jobs[id] = j
	s.evictOldLocked()
	s.mu.Unlock()

	// Non-blocking send -- if the queue is full we still record the job
	// but it'll fail immediately. In practice 64 slots is more than
	// enough; an analyst would never queue that many simultaneously.
	select {
	case s.pending <- pendingJob{id: id, work: work}:
	default:
		s.mu.Lock()
		j.Status = StatusFailed
		j.Error = "job queue full"
		now := time.Now().UTC()
		j.EndedAt = &now
		s.mu.Unlock()
	}
	return j
}

// Get returns a copy of the job with the given ID, or nil if not found.
// A copy (not a pointer to internal state) is returned so callers can
// inspect it without holding the lock.
func (s *Store) Get(id string) *Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil
	}
	cp := *j
	cp.cancel = nil // don't leak the cancel function outside the store
	return &cp
}

// List returns a snapshot of all jobs, newest first. The slice is
// freshly allocated; callers may mutate it without affecting the store.
func (s *Store) List() []*Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		cp := *j
		cp.cancel = nil
		out = append(out, &cp)
	}
	// Newest first by StartedAt.
	sortJobsByStartDesc(out)
	return out
}

// Cancel asks the worker handling the given job to stop. The job moves
// to StatusCancelled once the worker checks its context. Returns true
// if the job was found and a cancel was issued.
func (s *Store) Cancel(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return false
	}
	if j.IsTerminal() {
		return false
	}
	if j.cancel != nil {
		j.cancel()
	}
	// The worker is responsible for setting StatusCancelled when its
	// context fires. We don't set it here to avoid racing with the
	// worker writing StatusComplete/Failed.
	return true
}

// SetProgress updates a job's progress string. Safe to call from inside
// a Work function; the running worker is the only goroutine expected to
// touch its own job's Progress field.
func (s *Store) SetProgress(id, progress string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		j.Progress = progress
	}
}

// worker is the background goroutine that pulls pending work and runs
// it. Multiple workers run in parallel (the count passed to NewStore).
func (s *Store) worker() {
	for {
		select {
		case <-s.stop:
			return
		case pj := <-s.pending:
			s.runJob(pj)
		}
	}
}

// runJob is the meat of the worker: transitions queued -> running,
// invokes the work function with a cancellable context, then transitions
// to a terminal state based on the outcome.
func (s *Store) runJob(pj pendingJob) {
	// Move to running state and stash the cancel.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // belt-and-braces; the work function should return cleanly

	s.mu.Lock()
	j, ok := s.jobs[pj.id]
	if !ok {
		// Job vanished -- shouldn't happen but defensive.
		s.mu.Unlock()
		return
	}
	if j.IsTerminal() {
		// Was cancelled before a worker picked it up.
		s.mu.Unlock()
		return
	}
	j.Status = StatusRunning
	j.cancel = cancel
	s.mu.Unlock()

	resultID, err := pj.work(ctx, j)

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-fetch in case it was already terminal-state-set by a cancel.
	j2, ok := s.jobs[pj.id]
	if !ok {
		return
	}
	now := time.Now().UTC()
	j2.EndedAt = &now
	j2.cancel = nil
	if err != nil {
		// Distinguish cancellation from genuine failure. If the context
		// was cancelled (Cancel() called), report it as cancelled rather
		// than failed -- different UX.
		if ctx.Err() == context.Canceled {
			j2.Status = StatusCancelled
			j2.Error = "cancelled by user"
		} else {
			j2.Status = StatusFailed
			j2.Error = err.Error()
		}
		return
	}
	j2.Status = StatusComplete
	j2.ResultID = resultID
}

// evictOldLocked drops the oldest terminal jobs to keep the store
// bounded. Caller holds s.mu.
func (s *Store) evictOldLocked() {
	if len(s.jobs) <= s.maxJobs {
		return
	}
	// Collect terminal jobs sorted by EndedAt (oldest first).
	var terminal []*Job
	for _, j := range s.jobs {
		if j.IsTerminal() {
			terminal = append(terminal, j)
		}
	}
	sortJobsByEndedAtAsc(terminal)
	// Drop enough to get back under cap.
	drop := len(s.jobs) - s.maxJobs
	for i := 0; i < drop && i < len(terminal); i++ {
		delete(s.jobs, terminal[i].ID)
	}
}

// newJobID returns a short random hex string used as job ID. 64 bits of
// randomness -- collision probability is negligible for the lifetime of
// a process.
func newJobID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "job_" + hex.EncodeToString(b[:])
}

// sortJobsByStartDesc sorts the slice in-place, newest StartedAt first.
// Stable so ties resolve in insertion order.
func sortJobsByStartDesc(js []*Job) {
	// Tiny n; insertion sort is fine and avoids pulling sort package.
	for i := 1; i < len(js); i++ {
		for k := i; k > 0 && js[k].StartedAt.After(js[k-1].StartedAt); k-- {
			js[k], js[k-1] = js[k-1], js[k]
		}
	}
}

// sortJobsByEndedAtAsc sorts in-place, oldest EndedAt first.
// Jobs without EndedAt (shouldn't appear in this path since callers
// pass only terminal ones) sort to the end via the nil check.
func sortJobsByEndedAtAsc(js []*Job) {
	for i := 1; i < len(js); i++ {
		for k := i; k > 0; k-- {
			a, b := js[k-1].EndedAt, js[k].EndedAt
			if a == nil {
				js[k], js[k-1] = js[k-1], js[k]
				continue
			}
			if b == nil {
				break
			}
			if a.Before(*b) {
				break
			}
			js[k], js[k-1] = js[k-1], js[k]
		}
	}
}
