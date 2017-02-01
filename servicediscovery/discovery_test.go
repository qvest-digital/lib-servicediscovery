package servicediscovery

import (
	"testing"
	"github.com/golang/mock/gomock"
	"github.com/miekg/dns"
	"time"
	"github.com/stretchr/testify/assert"
	"fmt"
	"net"
)

func TestServiceDiscovery_DiscoverService_NoEntries(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient}

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: 0}}, time.Duration(0), nil)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is thrown
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "Service lookup: No SRV entry in DNS response")

	// and the target cache is empty
	a.Equal(len(testSubject.targetCache), 0)
}

func TestServiceDiscovery_DiscoverService(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient,
		targetCache: make(map[string]net.IP)}

	// expect
	srvCall := mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port: 1},
			&dns.SRV{
				Target: "hostname2.",
				Port: 2},
		}},
		time.Duration(0), nil)

	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.A{
				A: net.IPv4(10,0,0,1)},
			&dns.A{
				A: net.IPv4(10,0,0,2)},
		}},
		time.Duration(0), nil).After(srvCall).Times(2)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then the correct ip and port is returned
	a.Equal("10.0.0.1", ip)
	a.Equal("1", port)
	a.NoError(err)

	// and the target cache contains the new entry
	a.Equal(testSubject.targetCache["hostname1"], net.IPv4(10,0,0,1))
}

func TestServiceDiscovery_DiscoverServiceCachedTarget(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient,
		targetCache: make(map[string]net.IP)}

	testSubject.targetCache["hostname1"] = net.IPv4(10,0,0,3)

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port: 1},
			&dns.SRV{
				Target: "hostname2.",
				Port: 2},
		}},
		time.Duration(0), nil).Times(2)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then the ip and port is returned
	a.Equal("10.0.0.3", ip)
	a.Equal("1", port)
	a.NoError(err)

	// and the target contains the entry is empty
	a.Equal(testSubject.targetCache["hostname1"], net.IPv4(10, 0, 0, 3))
}

func TestServiceDiscovery_SRV_NoSuccess(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient}

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: 1},
		},
		time.Duration(0), nil)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is returned
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "Service lookup: DNS query did not succeed")

	// and the target cache is empty
	a.Equal(len(testSubject.targetCache), 0)
}

func TestServiceDiscovery_Exchange_SRV_Fail(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient}

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(nil, time.Duration(0), fmt.Errorf("error"))

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is returned
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "error")

	// and the target cache is empty
	a.Equal(len(testSubject.targetCache), 0)
}

func TestServiceDiscovery_Resolve_A_Fail(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient,
		targetCache: make(map[string]net.IP)}

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port: 1},
			&dns.SRV{
				Target: "hostname2.",
				Port: 2},
		}},
		time.Duration(0), nil)

	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(nil, time.Duration(0), fmt.Errorf("error")).Times(2)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is returned
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "Service lookup: No SRV entry in DNS response")

	// and the target cache is empty
	a.Equal(len(testSubject.targetCache), 0)
}

func TestServiceDiscovery_A_NoSuccess(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient,
		targetCache: make(map[string]net.IP)}

	// expect
	srvCall := mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port: 1},
			&dns.SRV{
				Target: "hostname2.",
				Port: 2},
		}},
		time.Duration(0), nil)

	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 1},
		Answer: []dns.RR{}},
		time.Duration(0), nil).After(srvCall).Times(2)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is returned
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "Service lookup: No SRV entry in DNS response")

	// and the target cache is empty
	a.Equal(len(testSubject.targetCache), 0)
}

func TestServiceDiscovery_NoARecords(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := consulServiceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client: mockDnsClient,
		targetCache: make(map[string]net.IP)}

	// expect
	srvCall := mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port: 1},
			&dns.SRV{
				Target: "hostname2.",
				Port: 2},
		}},
		time.Duration(0), nil)

	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{}},
		time.Duration(0), nil).After(srvCall).Times(2)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then a error is returned
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "Service lookup: No SRV entry in DNS response")

	// and the target cache is empty
	a.Equal(len(testSubject.targetCache) ,0)
}

func TestServiceDiscovery_Constructor_IP(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, _ := NewConsulServiceDiscovery("127.0.0.1:53")
	castedTestSubject := testSubject.(*consulServiceDiscovery)

	// then
	a.Equal(castedTestSubject.dnsServer, "127.0.0.1:53")
	a.Equal(castedTestSubject.targetCache, make(map[string]net.IP))
	a.Equal(castedTestSubject.dnsSearch, ".service.consul")
	a.Equal(castedTestSubject.client, &dns.Client{})
}

func TestServiceDiscovery_Constructor_Hostname(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, _ := NewConsulServiceDiscovery("localhost:53")
	castedTestSubject := testSubject.(*consulServiceDiscovery)

	// then
	a.Equal(castedTestSubject.dnsServer, "[::1]:53")
	a.Equal(castedTestSubject.targetCache, make(map[string]net.IP))
	a.Equal(castedTestSubject.dnsSearch, ".service.consul")
	a.Equal(castedTestSubject.client, &dns.Client{})
}


func TestServiceDiscovery_Constructor_WrongArg(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, err := NewConsulServiceDiscovery("localhost::53")

	// then
	a.Nil(testSubject)
	a.Error(err)
}

func TestServiceDiscovery_Constructor_UnknownHost(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, err := NewConsulServiceDiscovery("unknown:53")

	// then
	a.Nil(testSubject)
	a.EqualError(err, "lookup unknown: no such host")
}
