package main

import (
	"encoding/json"
	"fmt"
	"go_stix/generator"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/TcM1911/stix2"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func removeExtension(fileName string) string {
	ext := filepath.Ext(fileName)
	return strings.TrimSuffix(fileName, ext)
}

// returns the id of the object containing the given substring
func findFileWithSubstr(dir string, fileNamePrefix string, substr string) string {

	files, err := os.ReadDir(dir)
	check(err)

	for _, file := range files {
		if strings.Contains(file.Name(), fileNamePrefix) {

			data, err := os.ReadFile(dir + file.Name())
			check(err)

			if strings.Contains(string(data), substr) {
				return removeExtension(file.Name())

			}

		}
	}
	return ""
}

// tries to match str and indicator.Pattern
func matchIndicator(indicator *stix2.Indicator, str *string) bool {
	pattern := strings.Split(indicator.Pattern, "'")[1]
	return strings.Contains(*str, pattern)

}

type Indicator struct {
	Id      string `json:"id"`
	Pattern string `json:"pattern"`
}

type IndicatorResult struct {
	Indicator stix2.Indicator
	Error     error
}

// contains every bundle inside the "objects/" directory for easier access
type cyberBundles struct {
	collections []stix2.Collection
	creator     string
}

// creates new cyberBundles object
func newCyberBundles(creatorIdentity *string) *cyberBundles {

	c := cyberBundles{
		collections: make([]stix2.Collection, 0, 100),
		creator:     *creatorIdentity,
	}
	return &c
}

// looks for an indicator that matches str
func (b *cyberBundles) FindMatchingIndicator(str string) int {

	var indicators []*stix2.Indicator = b.getAllIndicators()

	//iterate over indicators
	for i, indicator := range indicators {

		pattern := strings.Split(indicator.Pattern, "'")[1]

		if strings.Contains(str, pattern) {
			//found it
			return i
		}
	}
	return -1

}

// returns the collection at index i
func (b *cyberBundles) getCollection(i int) *stix2.Collection {
	return &(b.collections[i])
}

// loads every single STIX bundle object
func (b *cyberBundles) LoadBundles(dir string) {

	files, err := os.ReadDir(dir)
	check(err)

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "bundle") {
			//found a new bundle to add to collections
			bundleId := removeExtension(file.Name())
			c := readBundle(dir, bundleId)
			b.AddCollection(c)
			fmt.Printf("just loaded bundle\n")
		}
	}
}

// returns all STIX indicators
func (b *cyberBundles) getAllIndicators() []*stix2.Indicator {

	indicators := make([]*stix2.Indicator, 0, cap(b.collections))

	for _, c := range b.collections {
		indicators = append(indicators, c.Indicators()...)
	}
	return indicators
}

// adds a collection object to the collections slice
func (b *cyberBundles) AddCollection(collection *stix2.Collection) {
	b.collections = append(b.collections, *collection)
}

// returns a slice of maps from a given collection.
// Each map corresponds to an object of the collection
func collectionToMaps(collection *stix2.Collection) []*map[string]any {

	// var l int = len(collection.AllObjects())

	var maps []*map[string]any = make([]*map[string]any, 0)

	for _, obj := range collection.AllObjects() {
		if reflect.TypeOf(obj).String() != "*stix2.Relationship" && reflect.TypeOf(obj).String() != "*stix2.Indicator" {

			res, err := json.Marshal(obj)
			check(err)

			var tmpMap map[string]any

			err = json.Unmarshal(res, &tmpMap)
			check(err)

			maps = append(maps, &tmpMap)
		}
	}
	return maps
}

// reads a bundle from file and stores it in a stix2.Collection
func readBundle(dir string, bundleId string) *stix2.Collection {
	data, err := os.ReadFile(dir + bundleId + ".json")
	check(err)

	c, err := stix2.FromJSON(data)
	check(err)
	return c
}

// a container to better marshal all objects retrieved by matching an indicator
type OutputContainer struct {
	Type    string            `json:"wazuh_event_type"`
	Objects []*map[string]any `json:"objects"`
}

func main() {

	//	idsChan := make(chan string)

	var argsLen int = len(os.Args)

	if argsLen < 2 {
		log.Fatal("no arguments found, exiting")
	}

	var argv string = os.Args[1]

	var inputObj *ActiveResponseInput

	inputObj, err := ParseArg(&argv)

	if err != nil {
		panic(err)
	}

	alertField, ok := inputObj.Params["alert"]
	if !ok {
		log.Fatal("input json doesn't contain any  \"alert\" field")
	}

	// fmt.Println(alertField)
	// fmt.Printf("\n\nalert type: %T\n\n", alertField)

	//get the actual alert contents
	var alertContent map[string]any = alertField.(map[string]any)

	//now extract the full_log field
	var fullLog string = alertContent["full_log"].(string)
	fmt.Println(fullLog)

	var b bool = false

	done := make(chan bool)

	if _, err := os.Stat("objects/"); err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir("objects", 0755)
			check(err)

			//generate base files
			go generator.CreateBaseFiles(done)
			b = true

		} else {
			check(err)
		}
	}

	if b {
		<-done
	}

	//load base objects
	cyberIdentity := findFileWithSubstr("objects/", "identity", "Cyber team")

	//get bundles that contain IoCs and related STIX objects
	bundles := newCyberBundles(&cyberIdentity)

	go func() {
		defer close(done)
		bundles.LoadBundles("objects/")
		done <- true
	}()

	inputString := fullLog

	//wait for all bundles to be loaded into the cyberBundles object
	<-done

	//does our input string (wazuh alert) match any indicator?
	var i int = bundles.FindMatchingIndicator(inputString)

	switch i {
	case -1:
		fmt.Fprintf(os.Stderr, "no matching indicator found. Exiting\n")
		return
	}

	collection := bundles.getCollection(i)

	//these maps are going to be marshaled and sent to wazuh as response
	maps := collectionToMaps(collection)

	container := OutputContainer{
		Type:    "Incident",
		Objects: maps,
	}

	data, err := json.MarshalIndent(container, "", "\t")
	check(err)

	fmt.Println(string(data))
}