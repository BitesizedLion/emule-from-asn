package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	http.HandleFunc("/generate", generateHandler)
	http.ListenAndServe(":8080", nil)
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	asn := r.URL.Query().Get("asn")
	if asn == "" {
		http.Error(w, "ASN parameter is missing", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}

	if !isValidASN(asn) {
		http.Error(w, "Invalid ASN format", http.StatusBadRequest)
		return
	}

	cacheFilename := fmt.Sprintf("cache/%s.dat", asn)
	if _, err := os.Stat(cacheFilename); err == nil {
		content, err := readFile(cacheFilename)
		if err != nil {
			http.Error(w, "Failed to read from cache: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(content))
		fmt.Println("Served from cache:", cacheFilename)
		return
	}

	ips, err := fetchIPs(asn)
	if err != nil {
		http.Error(w, "Failed to fetch IPs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	blocklist := convertToEmuleDatFormat(asn, ips)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(blocklist))

	if err := writeFile(cacheFilename, blocklist); err != nil {
		fmt.Println("Failed to write to cache:", err)
	}

	fmt.Println("Generated and served blocklist for", asn)
}

func fetchIPs(asn string) ([]string, error) {
	conn, err := net.Dial("tcp", "whois.radb.net:43")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	query := "-i origin " + asn + "\r\n"
	_, err = conn.Write([]byte(query))
	if err != nil {
		return nil, err
	}

	var response strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		response.Write(buf[:n])
	}

	lines := strings.Split(response.String(), "\n")
	var ips []string
	for _, line := range lines {
		if strings.HasPrefix(line, "route:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ips = append(ips, fields[1])
			}
		}
	}

	return ips, nil
}

func convertToEmuleDatFormat(asn string, ips []string) string {
	var blocklist strings.Builder
	for _, ip := range ips {
		ipRange := cidrToRange(ip)
		blocklist.WriteString(fmt.Sprintf("%s , 000 , %s\n", ipRange, asn))
	}
	return blocklist.String()
}

func cidrToRange(cidr string) string {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}

	networkIP := ipNet.IP
	broadcastIP := make(net.IP, len(networkIP))
	for i := range networkIP {
		broadcastIP[i] = networkIP[i] | ^ipNet.Mask[i]
	}

	networkIPStr := ip.String()
	broadcastIPStr := broadcastIP.String()
	return fmt.Sprintf("%s - %s", networkIPStr, broadcastIPStr)
}

func writeFile(filename, content string) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}
	return nil
}

func readFile(filename string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func isValidASN(asn string) bool {
	asn = strings.TrimPrefix(asn, "AS")
	asnInt, err := strconv.Atoi(asn)
	if err != nil {
		return false
	}

	// public only lol
	if (asnInt >= 1 && asnInt <= 64511) || (asnInt >= 65536 && asnInt <= 4199999999) {
		return true
	}

	return false
}
