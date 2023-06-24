package monitor

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/protocol/consts"
)

type stats struct {
	PID statsPID `json:"pid"`
	OS  statsOS  `json:"os"`
}

type statsPID struct {
	CPU   float64 `json:"cpu"`
	RAM   uint64  `json:"ram"`
	Conns int     `json:"conns"`
}

type statsOS struct {
	CPU      float64 `json:"cpu"`
	RAM      uint64  `json:"ram"`
	TotalRAM uint64  `json:"total_ram"`
	LoadAvg  float64 `json:"load_avg"`
	Conns    int     `json:"conns"`
}

var (
	monitPIDCPU   atomic.Value
	monitPIDRAM   atomic.Value
	monitPIDConns atomic.Value

	monitOSCPU      atomic.Value
	monitOSRAM      atomic.Value
	monitOSTotalRAM atomic.Value
	monitOSLoadAvg  atomic.Value
	monitOSConns    atomic.Value
)

var (
	mutex sync.RWMutex
	once  sync.Once
	data  = &stats{}
)

// New creates a new middleware handler
func New(config ...Config) frame.HandlerFunc {
	// Set default config
	cfg := configDefault(config...)

	// Start routine to update statistics
	once.Do(func() {
		p, _ := process.NewProcess(int32(os.Getpid())) //nolint:errcheck // TODO: Handle error

		updateStatistics(p)

		go func() {
			for {
				time.Sleep(cfg.Refresh)

				updateStatistics(p)
			}
		}()
	})

	// Return new handler
	//nolint:errcheck // Ignore the type-assertion errors
	return func(c context.Context, ctx *frame.Context) {
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(ctx) {
			ctx.Next(c)
			return
		}

		if strings.ToLower(string(ctx.Method())) != "get" {
			ctx.JSON(405, consts.StatusMethodNotAllowed)
			return
		}
		if strings.ToLower(string(ctx.GetHeader(consts.HeaderAccept))) == consts.MIMEApplicationJSON || cfg.APIOnly {
			mutex.Lock()
			data.PID.CPU, _ = monitPIDCPU.Load().(float64)
			data.PID.RAM, _ = monitPIDRAM.Load().(uint64)
			data.PID.Conns, _ = monitPIDConns.Load().(int)

			data.OS.CPU, _ = monitOSCPU.Load().(float64)
			data.OS.RAM, _ = monitOSRAM.Load().(uint64)
			data.OS.TotalRAM, _ = monitOSTotalRAM.Load().(uint64)
			data.OS.LoadAvg, _ = monitOSLoadAvg.Load().(float64)
			data.OS.Conns, _ = monitOSConns.Load().(int)
			mutex.Unlock()
			ctx.JSON(200, data)
			return
		}
		ctx.HtmlBytes(200, []byte(cfg.index))
	}
}

func updateStatistics(p *process.Process) {
	pidCPU, err := p.CPUPercent()
	if err == nil {
		monitPIDCPU.Store(pidCPU / 10)
	}

	if osCPU, err := cpu.Percent(0, false); err == nil && len(osCPU) > 0 {
		monitOSCPU.Store(osCPU[0])
	}

	if pidRAM, err := p.MemoryInfo(); err == nil && pidRAM != nil {
		monitPIDRAM.Store(pidRAM.RSS)
	}

	if osRAM, err := mem.VirtualMemory(); err == nil && osRAM != nil {
		monitOSRAM.Store(osRAM.Used)
		monitOSTotalRAM.Store(osRAM.Total)
	}

	if loadAvg, err := load.Avg(); err == nil && loadAvg != nil {
		monitOSLoadAvg.Store(loadAvg.Load1)
	}

	pidConns, err := net.ConnectionsPid("tcp", p.Pid)
	if err == nil {
		monitPIDConns.Store(len(pidConns))
	}

	osConns, err := net.Connections("tcp")
	if err == nil {
		monitOSConns.Store(len(osConns))
	}
}
