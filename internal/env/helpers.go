package env

import (
	"os"
	"strconv"
	"time"
)

func GetEnvAsFloat(key string, defaultVal float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return defaultVal
}

func GetEnvAsInt(key string, defaultVal int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func GetEnvAsInt32(key string, defaultVal int32) int32 {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return defaultVal
	}
	return int32(parsed)
}

func GetEnvAsDuration(key string, defaultVal time.Duration) time.Duration {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		return defaultVal
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return defaultVal
	}
	return parsed
}
