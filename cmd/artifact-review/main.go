// Command artifact-review is a host-centric DFIR review tool for
// Zimmerman/EZ Tools and Hayabusa CSV output.
//
// Usage:
//
//	artifact-review [--case <dir>] [--addr <host:port>] [--no-open]
//
// The binary embeds its own UI and serves it from a local HTTP server.
// On startup the default browser is opened to the UI; pass --no-open to
// suppress that.
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/example/artifact-review/internal/ingest"
	"github.com/example/artifact-review/internal/jobs"
	"github.com/example/artifact-review/internal/marks"
	"github.com/example/artifact-review/internal/preprocess"
	"github.com/example/artifact-review/internal/server"
)

//go:embed all:static
var embedded embed.FS

func main() {
	caseDir := flag.String("case", "", "path to a case directory to open on launch")
	addr := flag.String("addr", "127.0.0.1:0", "address to bind the local UI server")
	noOpen := flag.Bool("no-open", false, "do not open the system browser on launch")
	// Concurrent upload/preprocess job count. 2 is the locked-in default
	// from the v0.11.0 design discussion: gets parallelism without
	// thrashing CPU-bound EZ Tools (when v0.11.1 lands those).
	uploadWorkers := flag.Int("upload-workers", 2, "number of concurrent upload/preprocess jobs")
	flag.Parse()

	// Carve the embedded FS down to the static/ subdirectory so URLs map
	// cleanly: "/foo.css" -> "static/foo.css".
	assets, err := fs.Sub(embedded, "static")
	if err != nil {
		log.Fatalf("embedded assets: %v", err)
	}

	cases := ingest.NewStore()
	mks := marks.New()
	js := jobs.NewStore(*uploadWorkers)
	defer js.Close()

	// Preprocessor: optional. Construction discovers PowerShell on the
	// PATH and extracts the embedded PS1 to a temp file. Failure is
	// not fatal -- /api/preprocess returns 503 and the UI suppresses
	// the wizard. This is the expected path on Linux/macOS where the
	// PS1 wouldn't work anyway.
	prep, err := preprocess.New()
	if err != nil {
		log.Printf("preprocessor disabled: %v", err)
	} else {
		log.Printf("preprocessor ready: %s", prep.PSPath())
		defer prep.Close()
	}

	if *caseDir != "" {
		if err := cases.Open(*caseDir); err != nil {
			log.Fatalf("open case %q: %v", *caseDir, err)
		}
		if err := mks.Open(*caseDir); err != nil {
			log.Printf("warning: load marks: %v", err)
		}
		log.Printf("opened case: %s (%d hosts)", *caseDir, len(cases.Case().Hosts))
	} else {
		log.Printf("no --case provided; use the Import button in the UI")
	}

	srv := server.New(cases, mks, js, prep, assets)
	httpSrv := &http.Server{
		Handler:      srv.Routes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // streaming-friendly
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	chosen := ln.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://127.0.0.1:%d/", chosen.Port)
	log.Printf("artifact-review listening on %s", url)

	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	if !*noOpen {
		go openBrowser(url)
	}

	// Wait for SIGINT/SIGTERM, then shut down cleanly so debounced mark
	// writes get a chance to flush.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Println("shutting down…")

	mks.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

// openBrowser pops the system default browser at url, with cross-platform
// dispatch. Failures are logged but non-fatal — the user can paste the URL
// themselves.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		// "start" is a cmd builtin; we wrap it in rundll32 to avoid shell
		// escaping issues with URLs that contain & or %.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default: // linux, freebsd, etc.
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open browser: %v (visit %s manually)", err, url)
	}
}
