package servicediscovery

import (
	"github.com/miekg/dns"
	"time"
)

type DnsClient interface {
	Exchange(*dns.Msg, string) (r *dns.Msg, rtt time.Duration, err error)
}

type ServiceDiscovery interface {
	DiscoverService(serviceName string) (ip string, port string, err error)
	DiscoverAllServiceInstances(serviceName string) (instances []ServiceInstance, err error)
}
