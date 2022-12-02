package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	server = os.Getenv("SERVER")
	url    = server + "/api/v1/entities"
	key    = os.Getenv("KEY")
	secret = os.Getenv("SECRET")
)

type Entities []Entity

type Attribute struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Entity  Entity `json:"entity"`
}

type Association struct {
	Comment string `json:"comment"`
	Entity  Entity `json:"entity"`
}

type Entity struct {
	Reputation   int64         `json:"reputation"`
	Type         string        `json:"type"`
	Descriptor   string        `json:"descriptor"`
	Value        string        `json:"value"`
	Attributes   []Attribute   `json:"attributes,omitempty"`
	Associations []Association `json:"associations,omitempty"`
}

var ent = make(chan Entities, 100000)

var routines = 0

func main() {
	for i := 0; i <= 100; i++ {
		go sendEntity()
	}

	err := exec.Command("python3", "-m", "cvdupdate", "update").Run()
	if err != nil {
		ErrorF(400, err.Error())
	}

	err = exec.Command("dd", "if=daily.cvd", "of=daily.tar.gz", "bs=512", "skip=1").Run()
	if err != nil {
		ErrorF(400, err.Error())
	}

	err = exec.Command("dd", "if=main.cvd", "of=main.tar.gz", "bs=512", "skip=1").Run()
	if err != nil {
		ErrorF(400, err.Error())
	}

	err = exec.Command("tar", "-xf", "daily.tar.gz").Run()
	if err != nil {
		ErrorF(400, err.Error())
	}

	err = exec.Command("tar", "-xf", "main.tar.gz").Run()
	if err != nil {
		ErrorF(400, err.Error())
	}

	files := map[string][]string{
		"mdb": {"daily.mdb", "main.mdb"},
		"hdb": {"daily.hdb", "main.hdb"},
		"hsb": {"daily.hsb", "main.hsb"},
	}

	for kind, elements := range files {
		for _, file := range elements {
			switch kind {
			case "mdb":
				go processMDB(file)
			case "hdb":
				go processHDB(file)
			case "hsb":
				go processHSB(file)
			case "ndb":
				go processNDB(file)
			case "ldb":
				go processLDB(file)
			}
			routines++
		}
	}

	for routines != 0 {
		time.Sleep(5 * time.Minute)
	}
}

func processMDB(path string) {
	file, err := os.Open(path)
	if err != nil {
		ErrorF(500, err.Error())
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		s := strings.Split(fileScanner.Text(), ":")
		if len(s) == 1 {
			continue
		}

		t := detectHash(s[1])

		n := strings.Split(s[2], "-")

		toSend := []Entity{
			{
				Reputation: -3,
				Type:       "malware",
				Value:      strings.ReplaceAll(n[0], ".", " "),
				Attributes: []Attribute{},
				Associations: []Association{
					{
						Entity: Entity{
							Reputation: -3,
							Type:       t,
							Value:      s[1],
							Attributes: []Attribute{},
						},
					},
				},
			},
		}
		ent <- toSend
	}

	fmt.Printf("finished: %s", path)

	routines--
}

func processHDB(path string) {
	file, err := os.Open(path)
	if err != nil {
		ErrorF(500, err.Error())
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		s := strings.Split(fileScanner.Text(), ":")
		if len(s) == 1 {
			continue
		}

		t := detectHash(s[0])

		n := strings.Split(s[2], "-")

		toSend := []Entity{{
			Reputation: -3,
			Type:       "malware",
			Value:      strings.ReplaceAll(n[0], ".", " "),
			Attributes: []Attribute{},
			Associations: []Association{
				{
					Entity: Entity{
						Reputation: -3,
						Type:       t,
						Value:      s[0],
						Attributes: []Attribute{},
					},
				},
			},
		}}

		ent <- toSend
	}

	fmt.Printf("finished: %s", path)
	
	routines--
}

func processHSB(path string) {
	file, err := os.Open(path)
	if err != nil {
		ErrorF(500, err.Error())
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		s := strings.Split(fileScanner.Text(), ":")
		if len(s) == 1 {
			continue
		}

		t := detectHash(s[0])

		n := strings.Split(s[2], "-")

		toSend := []Entity{{
			Reputation: -3,
			Type:       "malware",
			Value:      strings.ReplaceAll(n[0], ".", " "),
			Attributes: []Attribute{},
			Associations: []Association{
				{
					Entity: Entity{
						Reputation: -3,
						Type:       t,
						Value:      s[0],
						Attributes: []Attribute{},
					},
				},
			},
		}}

		ent <- toSend
	}

	fmt.Printf("finished: %s", path)

	routines--
}

func processNDB(path string) {
	file, err := os.Open(path)
	if err != nil {
		ErrorF(500, err.Error())
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		s := strings.Split(fileScanner.Text(), ":")
		if len(s) == 1 {
			continue
		}

		n := strings.Split(s[0], "-")

		ndb := Association{
			Entity: Entity{
				Reputation: -3,
				Type:       "clamav-ndb",
				Value:      s[3],
			},
		}

		ndb.Entity.Attributes = append(ndb.Entity.Attributes, Attribute{
			Name: "target",
			Entity: Entity{
				Reputation: 0,
				Type:       "clamav-ndb-target",
				Value:      s[1],
			},
		})

		ndb.Entity.Attributes = append(ndb.Entity.Attributes, Attribute{
			Name: "offset",
			Entity: Entity{
				Reputation: 0,
				Type:       "clamav-ndb-offset",
				Value:      s[2],
			},
		})

		if len(s) == 5 {
			ndb.Entity.Attributes = append(ndb.Entity.Attributes, Attribute{
				Name: "min",
				Entity: Entity{
					Reputation: 0,
					Type:       "clamav-ndb-min",
					Value:      s[4],
				},
			})
		} else if len(s) == 6 {
			ndb.Entity.Attributes = append(ndb.Entity.Attributes, Attribute{
				Name: "min",
				Entity: Entity{
					Reputation: 0,
					Type:       "clamav-ndb-min",
					Value:      s[4],
				},
			})

			ndb.Entity.Attributes = append(ndb.Entity.Attributes, Attribute{
				Name: "max",
				Entity: Entity{
					Reputation: 0,
					Type:       "clamav-ndb-max",
					Value:      s[5],
				},
			})
		}

		malware := Entity{
			Reputation: -3,
			Type:       "malware",
			Value:      strings.ReplaceAll(n[0], ".", " "),
			Attributes: []Attribute{
				{
					Name: "source",
					Entity: Entity{
						Reputation: 0,
						Type:       "text",
						Value:      "ClamAV Signatures",
					},
				},
			},
		}

		malware.Associations = append(malware.Associations, ndb)

		toSend := Entities{malware}

		ent <- toSend
	}

	fmt.Printf("finished: %s", path)

	routines--
}

func processLDB(path string) {
	file, err := os.Open(path)
	if err != nil {
		ErrorF(500, err.Error())
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		s := strings.Split(fileScanner.Text(), ";")
		if len(s) == 1 {
			continue
		}

		n := strings.Split(s[0], "-")

		var ldbValue = ""

		for i, v := range s {
			if i < 3 {
				continue
			}
			var separator string
			if ldbValue == "" {
				separator = ""
			} else {
				separator = ";"
			}

			ldbValue = fmt.Sprintf("%s%s%s", ldbValue, separator, v)

		}

		ldb := Association{
			Entity: Entity{
				Reputation: -3,
				Type:       "clamav-ldb",
				Value:      ldbValue,
			},
		}

		ldb.Entity.Attributes = append(ldb.Entity.Attributes, Attribute{
			Name: "target",
			Entity: Entity{
				Reputation: 0,
				Type:       "clamav-ldb-target",
				Value:      s[1],
			},
		})

		ldb.Entity.Attributes = append(ldb.Entity.Attributes, Attribute{
			Name: "expression",
			Entity: Entity{
				Reputation: 0,
				Type:       "clamav-ldb-expression",
				Value:      s[2],
			},
		})

		malware := Entity{
			Reputation: -3,
			Type:       "malware",
			Value:      strings.ReplaceAll(n[0], ".", " "),
			Attributes: []Attribute{
				{
					Name: "source",
					Entity: Entity{
						Reputation: 0,
						Type:       "text",
						Value:      "ClamAV Signatures",
					},
				},
			},
		}

		malware.Associations = append(malware.Associations, ldb)

		toSend := Entities{malware}

		ent <- toSend
	}

	fmt.Printf("finished: %s", path)

	routines--
}

func detectHash(hash string) string {
	bytes := []byte(hash)
	var t string
	if len(bytes) == 16 {
		t = "md5"
	} else if len(bytes) == 40 {
		t = "sha1"
	} else if len(bytes) == 32 {
		t = "md5"
	} else if len(bytes) == 64 {
		t = "sha256"
	}
	return t
}

func sendEntity() {
	for {
		l := <-ent
		j, err := json.Marshal(l)
		if err != nil {
			ErrorF(400, "%s: %v", err.Error(), l)
			continue
		}
		for {
			e := doPost(url, j)
			if e == nil {
				break
			} else if e.Code <= 499 {
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
