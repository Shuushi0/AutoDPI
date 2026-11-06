package ui

import "sync/atomic"

func atomicAdd(p *int32, d int32) int32   { return atomic.AddInt32(p, d) }
func atomicLoad(p *int32) int32           { return atomic.LoadInt32(p) }
func atomicCAS(p *int32, o, n int32) bool { return atomic.CompareAndSwapInt32(p, o, n) }
