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
	if activeEngine != nil {
		activeEngine.dispatch(unsafe.Pointer(conn), int(routeID))
	} else {
		C.conn_notfound(conn)
	}
}
