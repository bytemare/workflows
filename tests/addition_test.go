package addition_test

import (
	"strconv"
	"testing"

	"github.com/bytemare/actions/internal"
)

type test struct {
	a, b, result int
}

func TestAddition(t *testing.T) {
	t.Parallel()

	tests := []test{
		{2, 3, 5},
		{0, 0, 0},
	}

	for i, addition := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()

			result := internal.Addition(addition.a, addition.b)
			if result != addition.result {
				t.Fatalf("%d: invalid result. Expected %d + %d = %d, got %d",
					i, addition.a, addition.b, addition.result, result)
			}
		})
	}
}

func FuzzAddition(f *testing.F) {
	f.Fuzz(func(t *testing.T, a, b int) {
		expected := a + b

		result := internal.Addition(a, b)
		if result != expected {
			t.Errorf("invalid result. Expected %d + %d = %d, got %d", a, b, expected, result)
		}
	})
}
