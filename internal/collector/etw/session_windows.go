//go:build windows && (amd64 || arm64)

package etw

// This file talks to the ETW API in advapi32.dll and tdh.dll directly.
// Go has no built-in ETW support, and the third-party Go ETW libraries either
// need cgo or are lightly maintained, so we declare the few structs and
// functions we need ourselves. The struct layouts below are copied from the
// Windows SDK headers (evntrace.h, evntcons.h, relogger.h) for 64-bit
// Windows; etw_windows_test.go checks their sizes.
//
// Flow of a session:
//
//	StartTraceW      create a real-time session named "trafficam"
//	EnableTraceEx2   switch on each provider for that session
//	OpenTraceW       attach a consumer; gives our callback to Windows
//	ProcessTrace     blocks, calling the callback for each event
//	ControlTraceW    (STOP) ends the session; ProcessTrace then returns

import (
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")

	tdh                    = windows.NewLazySystemDLL("tdh.dll")
	procTdhGetPropertySize = tdh.NewProc("TdhGetPropertySize")
	procTdhGetProperty     = tdh.NewProc("TdhGetProperty")
)

// Provider GUIDs (from "logman query providers").
var (
	kernelNetworkGUID = windows.GUID{Data1: 0x7dd42a49, Data2: 0x5329, Data3: 0x4832, Data4: [8]byte{0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}}
	dnsClientGUID     = windows.GUID{Data1: 0x1c95126e, Data2: 0x7eea, Data3: 0x49a9, Data4: [8]byte{0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}}
	kernelProcessGUID = windows.GUID{Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b, Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}}
)

const (
	wnodeFlagTracedGUID            = 0x00020000
	eventTraceRealTimeMode         = 0x00000100
	eventTraceControlQuery         = 0
	eventTraceControlStop          = 1
	eventControlCodeEnableProvider = 1
	traceLevelVerbose              = 5
	processTraceModeRealTime       = 0x00000100
	processTraceModeEventRecord    = 0x10000000
	clockSystemTime                = 2 // timestamps as FILETIME

	keywordKernelNetworkIPv4 = 0x10
	keywordKernelNetworkIPv6 = 0x20
	keywordKernelProcess     = 0x10 // WINEVENT_KEYWORD_PROCESS

	invalidProcessTraceHandle = ^uint64(0)
	maxLoggerNameChars        = 1024
)

// wnodeHeader is WNODE_HEADER (48 bytes).
type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// eventTraceProperties is EVENT_TRACE_PROPERTIES (120 bytes). Windows
// expects the session name to follow it in the same allocation.
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32 // KB per buffer
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32 // seconds
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// propsBuffer is EVENT_TRACE_PROPERTIES plus room for the session name.
type propsBuffer struct {
	p    eventTraceProperties
	name [maxLoggerNameChars]uint16
}

func newProps() *propsBuffer {
	b := &propsBuffer{}
	b.p.Wnode.BufferSize = uint32(unsafe.Sizeof(*b))
	b.p.Wnode.Flags = wnodeFlagTracedGUID
	b.p.Wnode.ClientContext = clockSystemTime
	b.p.LogFileMode = eventTraceRealTimeMode
	b.p.BufferSize = 64 // KB
	b.p.MinimumBuffers = 8
	b.p.MaximumBuffers = 64 // up to 4 MB of kernel memory while we catch up
	b.p.FlushTimer = 1
	b.p.LoggerNameOffset = uint32(unsafe.Offsetof(b.name))
	return b
}

// eventDescriptor is EVENT_DESCRIPTOR (16 bytes).
type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// eventHeader is EVENT_HEADER (80 bytes).
type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      windows.GUID
}

// eventRecord is EVENT_RECORD (112 bytes), what our callback receives.
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     uint32 // ProcessorNumber, Alignment, LoggerId
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          unsafe.Pointer
	UserContext       uintptr
}

// eventTraceHeader is EVENT_TRACE_HEADER (48 bytes); only here for layout.
type eventTraceHeader struct {
	Size          uint16
	FieldTypeFlag uint16
	Version       uint32
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	GUID          windows.GUID
	ProcessorTime uint64
}

// eventTrace is EVENT_TRACE (88 bytes); only here for layout.
type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

// traceLogfileHeader is TRACE_LOGFILE_HEADER (280 bytes); only here for layout.
type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGUID    windows.GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           [172]byte // TIME_ZONE_INFORMATION
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW (448 bytes), given to OpenTraceW.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// propertyDataDescriptor is PROPERTY_DATA_DESCRIPTOR, used to ask TDH for a
// named field of an event.
type propertyDataDescriptor struct {
	PropertyName uint64 // pointer to a UTF-16 name
	ArrayIndex   uint32
	Reserved     uint32
}

// session is one running ETW real-time session plus its consumer.
type session struct {
	name   string
	handle uint64        // from StartTraceW (controller side)
	trace  uint64        // from OpenTraceW (consumer side)
	done   chan struct{} // closed when ProcessTrace returns
	err    error         // why ProcessTrace returned (read after done)
	stop   sync.Once
}

// handler gets every event. It runs on the ETW thread, so it must be quick
// and must not block. Only one session per process is supported (the
// callback is a package-level function, because Go can create only a
// limited number of Windows callbacks).
type handler func(rec *eventRecord)

var (
	activeHandler atomic.Pointer[handler]
	callbackPanic atomic.Value // first panic text seen in the callback, if any
	eventCallback = syscall.NewCallback(func(rec *eventRecord) uintptr {
		defer func() {
			// A panic must never escape into Windows code: that would kill the
			// process. Remember it and keep going.
			if r := recover(); r != nil {
				callbackPanic.CompareAndSwap(nil, fmt.Sprintf("%v\n%s", r, debug.Stack()))
			}
		}()
		if h := activeHandler.Load(); h != nil {
			(*h)(rec)
		}
		return 0
	})
)

// errAccessDenied is returned when trafficam is not running as administrator.
var errAccessDenied = errors.New("etw: access denied (run as administrator or as the trafficam Windows service)")

// startSession creates the session, enables the providers and starts
// delivering events to h on a background thread.
func startSession(name string, h handler) (*session, error) {
	s := &session{name: name, done: make(chan struct{})}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	// A previous trafficam that crashed leaves its session behind (ETW
	// sessions outlive the process). Stop it so we can start fresh.
	stopByName(name)

	props := newProps()
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&props.p)))
	if err := winErr(r); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, errAccessDenied
		}
		return nil, fmt.Errorf("etw: StartTrace: %w", err)
	}

	enable := func(g *windows.GUID, keywords uint64) error {
		r, _, _ := procEnableTraceEx2.Call(uintptr(s.handle), uintptr(unsafe.Pointer(g)),
			eventControlCodeEnableProvider, traceLevelVerbose, uintptr(keywords), 0, 0, 0)
		return winErr(r)
	}
	if err := enable(&kernelNetworkGUID, keywordKernelNetworkIPv4|keywordKernelNetworkIPv6); err != nil {
		stopByName(name)
		return nil, fmt.Errorf("etw: enable Kernel-Network: %w", err)
	}
	// DNS-Client and Kernel-Process help but are not essential: carry on
	// without them if a locked-down machine refuses.
	var softErr error
	if err := enable(&dnsClientGUID, 0); err != nil { // 0 = all keywords
		softErr = errors.Join(softErr, fmt.Errorf("etw: enable DNS-Client: %w", err))
	}
	if err := enable(&kernelProcessGUID, keywordKernelProcess); err != nil {
		softErr = errors.Join(softErr, fmt.Errorf("etw: enable Kernel-Process: %w", err))
	}

	activeHandler.Store(&h)
	lf := &eventTraceLogfile{
		LoggerName:          namePtr,
		ProcessTraceMode:    processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: eventCallback,
	}
	r, _, _ = procOpenTraceW.Call(uintptr(unsafe.Pointer(lf)))
	s.trace = uint64(r)
	if s.trace == invalidProcessTraceHandle {
		err := windows.GetLastError()
		stopByName(name)
		return nil, fmt.Errorf("etw: OpenTrace: %v", err)
	}

	go func() {
		defer close(s.done)
		defer func() {
			if r := recover(); r != nil {
				s.err = fmt.Errorf("etw: ProcessTrace panicked: %v", r)
			}
		}()
		// ProcessTrace blocks until the session is stopped.
		r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&s.trace)), 1, 0, 0)
		s.err = winErr(r)
	}()
	return s, softErr
}

// Close stops the session and waits (briefly) for the consumer to finish.
func (s *session) Close() {
	s.stop.Do(func() {
		stopByName(s.name)
		procCloseTrace.Call(uintptr(s.trace))
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
		}
		activeHandler.Store(nil)
	})
}

// lost asks Windows how many events it had to throw away because we did not
// read them fast enough.
func (s *session) lost() (events, buffers uint32) {
	props := newProps()
	namePtr, _ := windows.UTF16PtrFromString(s.name)
	r, _, _ := procControlTraceW.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&props.p)), eventTraceControlQuery)
	if r != 0 {
		return 0, 0
	}
	return props.p.EventsLost, props.p.RealTimeBuffersLost
}

func stopByName(name string) {
	props := newProps()
	namePtr, _ := windows.UTF16PtrFromString(name)
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&props.p)), eventTraceControlStop)
}

func winErr(r uintptr) error {
	if r == 0 {
		return nil
	}
	return syscall.Errno(r)
}

// userData returns the event payload. Only valid during the callback.
func (rec *eventRecord) userData() []byte {
	if rec.UserData == nil || rec.UserDataLength == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(rec.UserData), rec.UserDataLength)
}

// property reads one named field of an event through TDH, Windows' event
// decoder. It works for any manifest provider without us knowing the exact
// layout, so we use it for the low-volume events (DNS, process start) and
// keep hand-written parsing for the high-volume network events.
// Only valid during the callback. Returns nil if the field does not exist.
func (rec *eventRecord) property(name string) []byte {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil
	}
	d := propertyDataDescriptor{PropertyName: uint64(uintptr(unsafe.Pointer(n))), ArrayIndex: 0xFFFFFFFF}
	var size uint32
	r, _, _ := procTdhGetPropertySize.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&size)))
	if r != 0 || size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = procTdhGetProperty.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(size), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return nil
	}
	return buf
}

func (rec *eventRecord) propUint32(name string) (uint32, bool) {
	b := rec.property(name)
	if len(b) < 4 {
		return 0, false
	}
	return *(*uint32)(unsafe.Pointer(&b[0])), true
}

func (rec *eventRecord) propString(name string) string {
	b := rec.property(name)
	if len(b) < 2 {
		return ""
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return windows.UTF16ToString(u)
}
