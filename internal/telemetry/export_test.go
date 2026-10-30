package telemetry

import sdkmetric "go.opentelemetry.io/otel/sdk/metric"

var (
	NewResource = newResource
	NewSampler  = newSampler
)

func SetExtraMetricReaders(readers ...sdkmetric.Reader) {
	extraMetricReaders = readers
}
