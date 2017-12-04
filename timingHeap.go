package cryptopals

type byteTiming struct {
	timing float64
	b      byte
}
type timingHeap []byteTiming

func (fh timingHeap) Len() int           { return len(fh) }
func (fh timingHeap) Less(i, j int) bool { return fh[j].timing < fh[i].timing }
func (fh timingHeap) Swap(i, j int)      { fh[i], fh[j] = fh[j], fh[i] }

func (fh *timingHeap) Push(x interface{}) {
	*fh = append(*fh, x.(byteTiming))
}

func (fh *timingHeap) Pop() interface{} {
	old := *fh
	n := len(old)
	res := old[n-1]
	*fh = old[0 : n-1]
	return res
}
