// Package memstat lets the benchmark runner query the memory use of a server process.
package memstat

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// Stats is the memory report printed by a server.
type Stats struct {
	HeapInuse  uint64 `json:"heap_inuse"` // bytes in in-use heap spans after a GC
	Sys        uint64 `json:"sys"`        // total bytes obtained from the OS
	Goroutines int    `json:"goroutines"`
}

// Prefix marks memory report lines on stdout.
const Prefix = "MEMSTATS "

// Serve prints a memory report (after a GC) for every line read from stdin.
func Serve() {
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			b, _ := json.Marshal(Stats{HeapInuse: m.HeapInuse, Sys: m.Sys, Goroutines: runtime.NumGoroutine()})
			fmt.Println(Prefix + string(b))
		}
	}()
}
