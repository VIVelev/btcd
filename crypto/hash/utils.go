package hash

import "math"

func isPrime(n int) bool {
	nsqrt := math.Sqrt(float64(n))
	for i := 2; float64(i) <= nsqrt; i++ {
		if n%i == 0 {
			return false
		}
	}

	return true
}

func firstNPrimes(n int) []int {
	primes := make([]int, n)
	for i, x := 0, 2; i < n; x++ {
		if isPrime(x) {
			primes[i] = x
			i++
		}
	}

	return primes
}

// fracBin returns the first n bits of fractional part of float f.
func fracBin(f float64, n int) uint64 {
	f -= math.Floor(f)           // get only the fractional part
	f *= math.Pow(2, float64(n)) // shift left
	return uint64(f)             // truncate and return
}
