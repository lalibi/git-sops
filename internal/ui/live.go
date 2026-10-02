package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"golang.org/x/term"
)

// live is the single in-place line (spinner or progress bar) shown at the bottom of the output.
type live struct {
	render func() string
}

func drawLocked() {
	if cur == nil {
		return
	}
	fmt.Fprint(os.Stdout, "\r\x1b[2K"+fit(cur.render()))
}

func startLive(l *live) {
	mu.Lock()
	cur = l
	drawLocked()
	mu.Unlock()
}

func stopLive() {
	mu.Lock()
	if cur != nil {
		fmt.Fprint(os.Stdout, "\r\x1b[2K")
		cur = nil
	}
	mu.Unlock()
}

// fit keeps the live line on one row so the next redraw can overwrite it cleanly.
func fit(s string) string {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 4 {
		return s
	}

	// Styled text carries escape codes, so truncate on visible width.
	return truncateVisible(s, width-1)
}

func truncateVisible(s string, max int) string {
	var b strings.Builder
	visible := 0
	inEscape := false

	for _, r := range s {
		switch {
		case inEscape:
			b.WriteRune(r)
			if r == 'm' {
				inEscape = false
			}
		case r == '\x1b':
			inEscape = true
			b.WriteRune(r)
		default:
			if visible >= max {
				continue
			}
			visible++
			b.WriteRune(r)
		}
	}

	return b.String() + "\x1b[0m"
}

var (
	spinFramesUnicode = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinFramesASCII   = []string{"|", "/", "-", "\\"}
)

type Spinner struct {
	title string
	frame int
	stop  chan struct{}
	live  bool
}

// Spin shows a spinner while work runs. Without a terminal it prints one status line instead.
func Spin(title string) *Spinner {
	s := &Spinner{title: title}

	if !fancy() {
		Infof("%s...", title)
		return s
	}

	frames := spinFramesUnicode
	if !unicodeOK() {
		frames = spinFramesASCII
	}

	s.live = true
	s.stop = make(chan struct{})
	startLive(&live{render: func() string {
		return paint(outRenderer, colorCyan, frames[s.frame%len(frames)]) + " " + s.title
	}})

	go func() {
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()

		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				mu.Lock()
				s.frame++
				drawLocked()
				mu.Unlock()
			}
		}
	}()

	return s
}

func (s *Spinner) SetTitle(title string) {
	mu.Lock()
	s.title = title
	drawLocked()
	mu.Unlock()
}

func (s *Spinner) end() {
	if s.live {
		close(s.stop)
		stopLive()
		s.live = false
	}
}

// Done replaces the spinner with a success line.
func (s *Spinner) Done(format string, args ...any) {
	s.end()
	Okf(format, args...)
}

// Fail replaces the spinner with an error line on stdout so it stays next to the step that failed.
func (s *Spinner) Fail(format string, args ...any) {
	s.end()
	msg := fmt.Sprintf(format, args...)
	if !fancy() {
		emit(os.Stdout, "[FAIL] "+msg)
		return
	}
	emit(os.Stdout, paint(outRenderer, colorRed, glyphSet().fail)+" "+msg)
}

// Task runs fn under a spinner titled title and reports the outcome.
func Task(title string, fn func() error) error {
	s := Spin(title)
	if err := fn(); err != nil {
		s.Fail("%s", title)
		return err
	}
	s.Done("%s", title)
	return nil
}

// Progress is a progress bar over a number of items or bytes.
type Progress struct {
	title   string
	total   int64
	done    int64
	bytes   bool
	detail  string
	live    bool
	lastRun time.Time
}

// NewProgress starts a bar. With bytes set, values render as sizes instead of counts.
func NewProgress(title string, total int64, bytes bool) *Progress {
	p := &Progress{title: title, total: total, bytes: bytes}

	if !fancy() {
		if bytes {
			Infof("%s...", title)
		}
		return p
	}

	p.live = true
	startLive(&live{render: p.render})
	return p
}

func (p *Progress) render() string {
	const barWidth = 24
	fill, empty := "█", "░"
	if !unicodeOK() {
		fill, empty = "#", "-"
	}

	ratio := 0.0
	if p.total > 0 {
		ratio = float64(p.done) / float64(p.total)
	}
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio * barWidth)

	bar := paint(outRenderer, colorGreen, strings.Repeat(fill, filled)) +
		Dim(strings.Repeat(empty, barWidth-filled))

	var amount string
	if p.bytes {
		amount = fmt.Sprintf("%s / %s", humanize.Bytes(uint64(p.done)), humanize.Bytes(uint64(p.total)))
	} else {
		amount = fmt.Sprintf("%d/%d", p.done, p.total)
	}

	line := fmt.Sprintf("%s %s %3.0f%%  %s", p.title, bar, ratio*100, Dim(amount))
	if p.detail != "" {
		line += "  " + Dim(p.detail)
	}
	return line
}

// Set records progress; redraws are throttled so fast downloads do not flood the terminal.
func (p *Progress) Set(done int64, detail string) {
	p.done = done
	p.detail = detail

	if !p.live {
		if !p.bytes && detail != "" {
			Infof("%s: %s", p.title, detail)
		}
		return
	}

	if now := time.Now(); done < p.total && now.Sub(p.lastRun) < 50*time.Millisecond {
		return
	} else {
		p.lastRun = now
	}

	mu.Lock()
	drawLocked()
	mu.Unlock()
}

// Write counts bytes, so a Progress can sit in an io.MultiWriter during a download.
func (p *Progress) Write(b []byte) (int, error) {
	p.Set(p.done+int64(len(b)), "")
	return len(b), nil
}

func (p *Progress) Finish(format string, args ...any) {
	if p.live {
		stopLive()
		p.live = false
	}
	Okf(format, args...)
}

// Abort removes the bar without reporting success.
func (p *Progress) Abort() {
	if p.live {
		stopLive()
		p.live = false
	}
}
