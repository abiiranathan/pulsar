package pulsar

/*
#include "bridge.h"
*/
import "C"
import (
	"unsafe"
)

//export goPulsarDispatcher
func goPulsarDispatcher(conn *C.PulsarConn, routeID C.int) {
	// activeEngine is published once by Listen via atomic.Pointer.Store
	// before the C event loop starts delivering requests. Loading it here
	// (rather than a bare pointer read) gives this cgo-invoked hot path a
	// proper happens-before relationship with that store, so the dispatch
	// goroutines are guaranteed to observe it instead of relying on
	// assumptions about init/startup ordering.
	if engine := activeEngine.Load(); engine != nil {
		engine.dispatch(unsafe.Pointer(conn), int(routeID))
	} else {
		C.conn_notfound(conn)
	}
}
