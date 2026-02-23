// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests_test

import (
	"fmt"

	"github.com/bytemare/workflows/tests/internal"
)

// ExampleAddition shows how to add numbers.
func ExampleAddition() {
	a := 2
	b := 3

	fmt.Printf("%d + %d = %d\n", a, b, internal.Addition(a, b))

	// Output: 2 + 3 = 5
}
