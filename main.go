package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
)

const (
	version = "1.0.0"
	tool    = "drone-tag"
	usage   = `
Tags each host matching an ip address or CIDR network in a newline separated file for a project. Only existing hosts will be changed.

Usage:
  drone-tag [options] <id> <filename>
  export LAIR_ID=<id>; drone-tag [options] <filename>
Options:
  -v              show version and exit
  -h              show usage and exit
  -k              allow insecure SSL connections
  -tags           a comma separated list of tags to add to every host that is imported
`
)

// LinesToIPList processes a list of IP addresses or networks in CIDR format.
// Returning a list of all possible IP addresses.
func LinesToIPList(lines []string) ([]string, error) {
	ipList := []string{}
	for _, line := range lines {
		if net.ParseIP(line) != nil {
			ipList = append(ipList, line)
		} else if ip, network, err := net.ParseCIDR(line); err == nil {
			for ip := ip.Mask(network.Mask); network.Contains(ip); increaseIP(ip) {
				ipList = append(ipList, ip.String())
			}
		} else {
			return ipList, fmt.Errorf("%s is not an IP Address or CIDR Network", line)
		}
	}
	return ipList, nil
}

// increases an IP by a single address.
func increaseIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ReadFileLines returns all the lines in a file.
func ReadFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func main() {
	showVersion := flag.Bool("v", false, "")
	insecureSSL := flag.Bool("k", false, "")
	tags := flag.String("tags", "", "")
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	lairPID := os.Getenv("LAIR_ID")
	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}
	if lairPID == "" {
		log.Fatal("Fatal: Missing LAIR_ID")
	}
	u, err := url.Parse(lairURL)
	if err != nil {
		log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		log.Fatal("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Fatal: Missing username and/or password")
	}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: *insecureSSL,
	})
	if err != nil {
		log.Fatalf("Fatal: Error setting up client: Error %s", err.Error())
	}

	lines, err := ReadFileLines(filename)
	if err != nil {
		log.Fatalf("Fatal: Unable to read file. Error %s", err.Error())
	}
	hosts, err := LinesToIPList(lines)
	if err != nil {
		log.Fatalf("Fatal: Error parsing ip addresses or networks. Error %s", err.Error())
	}

	hostTags := []string{}
	if *tags == "" {
		log.Fatal("Fatal: No tags provided by -tags")
	}
	hostTags = strings.Split(*tags, ",")

	exproject, err := c.ExportProject(lairPID)
	if err != nil {
		log.Fatalf("Fatal: Unable to export project. Error %s", err.Error())
	}

	project := &lair.Project{
		ID:   lairPID,
		Tool: tool,
		Commands: []lair.Command{lair.Command{
			Tool: tool,
		}},
	}

	for _, ip := range hosts {
		for i := range exproject.Hosts {
			host := exproject.Hosts[i]
			if host.IPv4 == ip {
				exproject.Hosts[i].Tags = append(exproject.Hosts[i].Tags, hostTags...)
			}
		}
	}

	for _, h := range exproject.Hosts {
		project.Hosts = append(project.Hosts, lair.Host{
			IPv4:           h.IPv4,
			LongIPv4Addr:   h.LongIPv4Addr,
			IsFlagged:      h.IsFlagged,
			LastModifiedBy: h.LastModifiedBy,
			MAC:            h.MAC,
			OS:             h.OS,
			Status:         h.Status,
			StatusMessage:  h.StatusMessage,
			Tags:           h.Tags,
			Hostnames:      h.Hostnames,
		})
	}

	res, err := c.ImportProject(&client.DOptions{ForcePorts: false}, project)
	if err != nil {
		log.Fatalf("Fatal: Unable to import project. Error %s", err)
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatalf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	log.Println("Success: Operation completed successfully")
}
