package servicediscovery

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestServiceDiscovery_DiscoverService_NoEntries(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := serviceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client:    mockDnsClient}

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: 0}}, time.Duration(0), nil)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is thrown
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "Service lookup: No SRV entry in DNS response")
}

func TestServiceDiscovery_DiscoverService(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := serviceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client:    mockDnsClient}

	// expect
	srvCall := mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port:   1},
			&dns.SRV{
				Target: "hostname2.",
				Port:   2},
		}},
		time.Duration(0), nil)

	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.A{
				A: net.IPv4(10, 0, 0, 1)},
			&dns.A{
				A: net.IPv4(10, 0, 0, 2)},
		}},
		time.Duration(0), nil).After(srvCall).Times(2)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then the correct ip and port is returned
	a.Equal("10.0.0.1", ip)
	a.Equal("1", port)
	a.NoError(err)
}

func TestServiceDiscovery_SRV_NoSuccess(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := serviceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client:    mockDnsClient}

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
}

func TestServiceDiscovery_Exchange_SRV_Fail(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := serviceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client:    mockDnsClient}

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(nil, time.Duration(0), fmt.Errorf("error"))

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is returned
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "error")
}

func TestServiceDiscovery_Resolve_A_Fail(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := serviceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client:    mockDnsClient}

	// expect
	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port:   1},
			&dns.SRV{
				Target: "hostname2.",
				Port:   2},
		}},
		time.Duration(0), nil)

	mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(nil, time.Duration(0), fmt.Errorf("error")).Times(2)

	// when
	ip, port, err := testSubject.DiscoverService("serviceName")

	// then an error is returned
	a.Equal("", ip)
	a.Equal("", port)
	a.EqualError(err, "Service lookup: No SRV entry in DNS response")
}

func TestServiceDiscovery_A_NoSuccess(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := serviceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client:    mockDnsClient}

	// expect
	srvCall := mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port:   1},
			&dns.SRV{
				Target: "hostname2.",
				Port:   2},
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
}

func TestServiceDiscovery_NoARecords(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// given: mocks
	mockDnsClient := NewMockDnsClient(ctrl)

	// given: test subject
	testSubject := serviceDiscovery{
		dnsServer: "dnsServer",
		dnsSearch: "dnsSearch",
		client:    mockDnsClient}

	// expect
	srvCall := mockDnsClient.EXPECT().Exchange(gomock.Any(), "dnsServer").Return(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: 0},
		Answer: []dns.RR{
			&dns.SRV{
				Target: "hostname1.",
				Port:   1},
			&dns.SRV{
				Target: "hostname2.",
				Port:   2},
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
}

func TestConsulServiceDiscovery_Constructor_IP(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, _ := NewConsulServiceDiscovery("127.0.0.1:53")
	castedTestSubject := testSubject.(*serviceDiscovery)

	// then
	a.Equal(castedTestSubject.dnsServer, "127.0.0.1:53")
	a.Equal(castedTestSubject.dnsSearch, ".service.consul")
	a.Equal(castedTestSubject.client, &dns.Client{})
}

func TestServiceDiscovery_Constructor_IP(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, _ := NewServiceDiscovery("127.0.0.1:53", "dnsSearch")
	castedTestSubject := testSubject.(*serviceDiscovery)

	// then
	a.Equal(castedTestSubject.dnsServer, "127.0.0.1:53")
	a.Equal(castedTestSubject.dnsSearch, "dnsSearch")
	a.Equal(castedTestSubject.client, &dns.Client{})
}

func TestConsulServiceDiscovery_Constructor_Hostname(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, _ := NewConsulServiceDiscovery("localhost:53")
	castedTestSubject := testSubject.(*serviceDiscovery)

	// then
	a.Equal(castedTestSubject.dnsServer, "[::1]:53")
	a.Equal(castedTestSubject.dnsSearch, ".service.consul")
	a.Equal(castedTestSubject.client, &dns.Client{})
}

func TestServiceDiscovery_Constructor_Hostname(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, _ := NewServiceDiscovery("localhost:53", "dnsSearch")
	castedTestSubject := testSubject.(*serviceDiscovery)

	// then
	a.Equal(castedTestSubject.dnsServer, "[::1]:53")
	a.Equal(castedTestSubject.dnsSearch, "dnsSearch")
	a.Equal(castedTestSubject.client, &dns.Client{})
}

func TestConsulServiceDiscovery_Constructor_WrongArg(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, err := NewConsulServiceDiscovery("localhost::53")

	// then
	a.Nil(testSubject)
	a.Error(err)
}

func TestServiceDiscovery_Constructor_WrongArg(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, err := NewServiceDiscovery("localhost::53", "dnsSearch")

	// then
	a.Nil(testSubject)
	a.Error(err)
}

func TestConsulServiceDiscovery_Constructor_UnknownHost(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, err := NewConsulServiceDiscovery("unknown:53")

	// then
	a.Nil(testSubject)
	a.EqualError(err, "lookup unknown: no such host")
}

func TestServiceDiscovery_Constructor_UnknownHost(t *testing.T) {
	a := assert.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// when
	testSubject, err := NewServiceDiscovery("unknown:53", "dnsSearch")

	// then
	a.Nil(testSubject)
	a.EqualError(err, "lookup unknown: no such host")
}
