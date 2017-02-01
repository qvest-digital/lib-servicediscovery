# lib servicediscovery

lib-servicediscovery is a small golang library that handles the service discovery via consul or any other DNS server that delivers SRV records.

## Packages 
 The library consists of the following packages:

- [servicediscovery] : The service discovery package

## Usage
First create an instance with NewConsulServiceDiscovery.

Calls to DiscoverService will deliver ip and port of the desired service.
If more than one instance of the service is present in Consul, the first randomized result will be returned.

Calls to DiscoverAllServiceInstances will deliver a list of all instances of the desired service. If no instance is found
a empty list will be returned.

 
