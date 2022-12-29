package websocket

type envelope struct {
	t      int
	msg    []byte
	filter FilterFunc
}
