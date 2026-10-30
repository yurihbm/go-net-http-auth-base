package env

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func lookup[T any](key string, defaultVal T, parse func(string) (T, error)) (T, error) {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		return defaultVal, nil
	}
	parsed, err := parse(value)
	if err != nil {
		return defaultVal, fmt.Errorf("%s is invalid: %w", key, err)
	}
	return parsed, nil
}

func LookupBool(key string, defaultVal bool) (bool, error) {
	return lookup(key, defaultVal, strconv.ParseBool)
}

func LookupFloat(key string, defaultVal float64) (float64, error) {
	return lookup(key, defaultVal, func(v string) (float64, error) {
		return strconv.ParseFloat(v, 64)
	})
}

func LookupInt(key string, defaultVal int) (int, error) {
	return lookup(key, defaultVal, strconv.Atoi)
}

func LookupInt32(key string, defaultVal int32) (int32, error) {
	return lookup(key, defaultVal, func(v string) (int32, error) {
		parsed, err := strconv.ParseInt(v, 10, 32)
		return int32(parsed), err
	})
}

func LookupDuration(key string, defaultVal time.Duration) (time.Duration, error) {
	return lookup(key, defaultVal, time.ParseDuration)
}
