package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/pkg/cpuonline"
	"golang.org/x/sys/unix"
	"k8s.io/klog"
)

type perfCounter struct {
	evType   int
	evConfig int
	enabled  bool
}

const (
	CPUCycleLabel       = "cpu_cycles"
	CPURefCycleLabel    = "cpu_ref_cycles"
	CPUInstructionLabel = "cpu_instr"
	CacheMissLabel      = "cache_miss"

	// Per /sys/kernel/debug/tracing/events/irq/softirq_entry/format
	// { 0, "HI" }, { 1, "TIMER" }, { 2, "NET_TX" }, { 3, "NET_RX" }, { 4, "BLOCK" }, { 5, "IRQ_POLL" }, { 6, "TASKLET" }, { 7, "SCHED" }, { 8, "HRTIMER" }, { 9, "RCU" }

	// IRQ vector to IRQ number
	IRQNetTX = 2
	IRQNetRX = 3
	IRQBlock = 4
)

var (
	Counters = map[string]perfCounter{
		CPUCycleLabel:       {unix.PERF_TYPE_HARDWARE, unix.PERF_COUNT_HW_CPU_CYCLES, true},
		CPURefCycleLabel:    {unix.PERF_TYPE_HARDWARE, unix.PERF_COUNT_HW_REF_CPU_CYCLES, true},
		CPUInstructionLabel: {unix.PERF_TYPE_HARDWARE, unix.PERF_COUNT_HW_INSTRUCTIONS, true},
		CacheMissLabel:      {unix.PERF_TYPE_HARDWARE, unix.PERF_COUNT_HW_CACHE_MISSES, true},
	}
	bpfPerfArrayPrefix = "_hc_reader"
)

type ProcessBPFMetrics struct {
	CGroupID       uint64
	PID            uint64
	ProcessRunTime uint64
	CPUCycles      uint64
	CPUInstr       uint64
	CacheMisses    uint64
	VecNR          [10]uint16 // irq counter, 10 is the max number of irq vectors
	Command        [16]byte
}

var (
	perfEvents = map[string][]int{}
	byteOrder  binary.ByteOrder
)

func init() {
	byteOrder = determineHostByteOrder()
}

const (
	tableProcessName = "processes"
	tableCPUFreqName = "cpu_freq_array"
	mapSize          = 10240
	cpuNumSize       = 128
)

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

func openPerfEvent(bpfMap *bpf.BPFMap, typ, config int) error {
	perfKey := fmt.Sprintf("%d:%d", typ, config)
	sysAttr := &unix.PerfEventAttr{
		Type:   uint32(typ),
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config: uint64(config),
	}

	if _, ok := perfEvents[perfKey]; ok {
		return nil
	}

	cpus, err := cpuonline.Get()
	if err != nil {
		return fmt.Errorf("failed to determine online cpus: %v", err)
	}

	res := []int{}

	for _, i := range cpus {
		cloexecFlags := unix.PERF_FLAG_FD_CLOEXEC

		fd, err := unix.PerfEventOpen(sysAttr, -1, int(i), -1, cloexecFlags)
		if fd < 0 {
			return fmt.Errorf("failed to open bpf perf event: %v", err)
		}
		err = bpfMap.Update(int32(i), uint32(fd))
		if err != nil {
			return fmt.Errorf("failed to update bpf map: %v", err)
		}
		res = append(res, int(fd))
	}

	perfEvents[perfKey] = res

	return nil
}

func closePerfEvent() {
	for _, vs := range perfEvents {
		for _, fd := range vs {
			unix.SetNonblock(fd, true)
			unix.Close(fd)
		}
	}
}

func getFilePathFromFD(fd uintptr) (string, error) {
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	path, err := os.Readlink(fdPath)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return absPath, nil
}

func collect(bpfModule *bpf.Module) {
	processes, err := bpfModule.GetMap("processes")
	must(err)
	cpuFreq, err := bpfModule.GetMap("cpu_freq_array")
	must(err)

	iterator := processes.Iterator(mapSize)
	var ct ProcessBPFMetrics
	var byteOrder binary.ByteOrder = determineHostByteOrder()
	valueSize := int(unsafe.Sizeof(ProcessBPFMetrics{}))
	keys := []uint32{}
	for iterator.Next() {
		keyBytes := iterator.Key()
		key := byteOrder.Uint32(keyBytes)
		data, err := processes.GetValue(key, valueSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get data: %v\n", err)
			continue // this only happens if there is a problem in the bpf code
		}
		err = binary.Read(bytes.NewBuffer(data), byteOrder, &ct)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decode received data: %v\n", err)
			continue // this only happens if there is a problem in the bpf code
		}
		fmt.Printf("%d: %s, %d, %d, %d\n", ct.PID, ct.Command, ct.ProcessRunTime, ct.CPUCycles, ct.CacheMisses)
		keys = append(keys, key)
	}
	for _, key := range keys {
		processes.DeleteKey(key)
	}

	iterator = cpuFreq.Iterator(cpuNumSize)
	var freq uint32
	valueSize = int(unsafe.Sizeof(freq))
	for iterator.Next() {
		keyBytes := iterator.Key()
		cpu := byteOrder.Uint32(keyBytes)
		data, err := cpuFreq.GetValue(cpu, valueSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get data: %v\n", err)
			continue // this only happens if there is a problem in the bpf code
		}
		err = binary.Read(bytes.NewBuffer(data), byteOrder, &freq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decode received data: %v\n", err)
			continue // this only happens if there is a problem in the bpf code
		}
		fmt.Printf("%d: %d\n", cpu, freq)
	}
}

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	bpfModule, err := bpf.NewModuleFromFile("kepler.bpf.o")
	must(err)
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	must(err)

	prog, err := bpfModule.GetProgram("kepler_trace")
	must(err)
	irq_prog, err := bpfModule.GetProgram("kepler_irq_trace")
	must(err)

	defer closePerfEvent()
	for arrayName, counter := range Counters {
		bpfPerfArrayName := arrayName + bpfPerfArrayPrefix
		bpfMap, err := bpfModule.GetMap(bpfPerfArrayName)
		must(err)
		perfErr := openPerfEvent(bpfMap, counter.evType, counter.evConfig)
		if perfErr != nil {
			// some hypervisors don't expose perf counters
			klog.Infof("failed to attach perf event %s: %v\n", bpfPerfArrayName, perfErr)
			counter.enabled = false
		}
	}

	_, err = prog.AttachTracepoint("sched:sched_switch")
	must(err)
	_, err = irq_prog.AttachTracepoint("irq:softirq_entry")
	// must(err)

	time.Sleep(time.Second * 1)
	collect(bpfModule)
	// fmt.Printf("===============no wait================\n")
	// collect(bpfModule)
	fmt.Printf("===============wait================\n")
	time.Sleep(time.Second * 2)
	collect(bpfModule)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
