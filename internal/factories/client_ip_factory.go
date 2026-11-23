package factories

import (
	"net/netip"

	"go-net-http-auth-base/internal/middlewares"
)

func ClientIPFactory(trustedProxies []netip.Prefix) middlewares.GlobalMiddleware {
	return middlewares.NewClientIPMiddleware(trustedProxies)
}
