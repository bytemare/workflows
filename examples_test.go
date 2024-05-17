package actions_test

import (
	"fmt"

	"github.com/bytemare/actions/internal"
)

// ExampleAddition shows how to add numbers.
func ExampleAddition() {
	a := 2
	b := 3

	fmt.Printf("%d + %d = %d\n", a, b, internal.Addition(a, b))

	// Output: 2 + 3 = 5
}
