package services_test

import "time"

var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func testClock() time.Time { return testNow }
