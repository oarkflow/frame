package idempotency

//go:generate msgp -o=response_msgp.go -io=false -unexported
type response struct {
	Headers    map[string][]string `msg:"hs"`
	Body       []byte              `msg:"b"`
	StatusCode int                 `msg:"sc"`
}
