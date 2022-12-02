package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

var (
	server       = os.Getenv("SERVER")
	location     = server + "/api/v1/geoip/location"
	organization = server + "/api/v1/geoip/organization"
	key          = os.Getenv("KEY")
	secret       = os.Getenv("SECRET")
)

type Geolocation struct {
	Segment        string  `json:"segment"`
	AccuracyRadius int64   `json:"accuracyRadius"`
	City           string  `json:"city"`
	Country        string  `json:"country"`
	CountryCode    string  `json:"countryCode"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
}

type Organization struct {
	Segment string `json:"segment"`
	ASN     int64  `json:"asn"`
	ASO     string `json:"aso"`
}

var geo = make(chan Geolocation, 100)
var geoDone = make(chan bool, 1)
var orgs = make(chan Organization, 100)
var orgsDone = make(chan bool, 1)

func main() {
	exec.Command("wget", os.Getenv("ASN"), "-O", "asn.zip").Run()
	exec.Command("wget", os.Getenv("BLOCK"), "-O", "block.zip").Run()
	exec.Command("unzip", "-j", "asn.zip").Run()
	exec.Command("unzip", "-j", "block.zip").Run()

	asn4 := readCsvFile("GeoLite2-ASN-Blocks-IPv4.csv")
	fmt.Println("ASN v4", len(asn4))

	asn6 := readCsvFile("GeoLite2-ASN-Blocks-IPv6.csv")
	fmt.Println("ASN v6", len(asn6))

	asn := append(asn4, asn6...)
	fmt.Println("ASN", len(asn))

	block4 := readCsvFile("GeoLite2-City-Blocks-IPv4.csv")
	fmt.Println("City v4", len(block4))

	block6 := readCsvFile("GeoLite2-City-Blocks-IPv6.csv")
	fmt.Println("City v6", len(block6))

	block := append(block4, block6...)
	fmt.Println("City", len(block))

	locations := readCsvFile("GeoLite2-City-Locations-en.csv")
	fmt.Println("Locations", len(locations))

	go processLocations(block, locations)

	go processOrganizations(asn)

	for i := 0; i <= 100; i++ {
		go sendLocations()
		go sendOrganizations()
	}

	<-orgsDone
	<-geoDone

	time.Sleep(1 * time.Minute)
}

func sendLocations() {
	for {
		l := <-geo
		j, err := json.Marshal(l)
		if err != nil {
			ErrorF(400, "%s: %v", err.Error(), l)
			continue
		}
		for {
			e := doPost(location, j)
			if e == nil {
				break
			}
		}
	}
}

func sendOrganizations() {
	for {
		o := <-orgs
		j, err := json.Marshal(o)
		if err != nil {
			ErrorF(400, "%s: %v", err.Error(), o)
			continue
		}
		for {
			e := doPost(organization, j)
			if e == nil || e.Code <= 499 {
				break
			}
		}
	}
}

func doPost(url string, data []byte) *Error {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return ErrorF(400, err.Error())
	}

	req.Header.Add("api-key", key)
	req.Header.Add("api-secret", secret)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return ErrorF(400, "retrying '%s' because of error '%s'", data, err.Error())
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return ErrorF(400, "retrying '%s' because of received status code '%d'", data, resp.StatusCode)
	}

	return nil
}

func processOrganizations(asn [][]string) {
	for i, a := range asn {
		if i == 0 {
			continue
		}
		n, err := strconv.ParseInt(a[1], 10, 64)
		if err != nil {
			ErrorF(400, "cannot parse ASN '%s' from '%v'", a[1], a)
			continue
		}
		orgs <- Organization{
			ASO:     a[2],
			ASN:     n,
			Segment: a[0],
		}
	}

	LogF(200, "organizations done")
	orgsDone <- true
}

func processLocations(block [][]string, locations [][]string) {
	for i, b := range block {
		if i == 0 {
			continue
		}
		for _, l := range locations {
			if b[1] == l[0] {
				accuracy, err := strconv.ParseInt(b[9], 10, 64)
				if err != nil {
					ErrorF(400, "cannot parse accuracy '%s' from '%v'", b[9], b)
					continue
				}

				latitude, err := strconv.ParseFloat(b[7], 64)
				if err != nil {
					ErrorF(400, "cannot parse latitude '%s' from '%v'", b[7], b)
					continue
				}

				longitude, err := strconv.ParseFloat(b[8], 64)
				if err != nil {
					ErrorF(400, "cannot parse longitude '%s' from '%v'", b[8], b)
					continue
				}

				city := l[10]
				if city == "" {
					city = "Unknown"
				}

				country := l[5]
				if country == "" {
					country = "Unknown"
				}

				countryCode := l[4]
				if countryCode == "" {
					countryCode = "Unknown"
				}

				geo <- Geolocation{
					Segment:        b[0],
					AccuracyRadius: accuracy,
					City:           city,
					Country:        country,
					CountryCode:    countryCode,
					Latitude:       latitude,
					Longitude:      longitude,
				}
			}
		}
	}

	LogF(200, "locations done")
	geoDone <- true
}

func readCsvFile(filePath string) [][]string {
	f, err := os.Open(filePath)
	if err != nil {
		ErrorF(500, "unable to read input file '%s' because of error '%s'", filePath, err.Error())
		panic(err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		ErrorF(500, "unable to parse csv file '%s' because of error '%s'", filePath, err.Error())
		panic(err)
	}

	return records
}
