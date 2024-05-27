package generator

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/TcM1911/stix2"
)

const StixDir = "/home/wazuh/objects/"

type id = stix2.Identifier

// returns a STIX relationship of type `t` between obj1 and obj2
func createRelationship(obj1 id, obj2 id, t stix2.RelationshipType) *stix2.Relationship {

	r, err := stix2.NewRelationship(
		t,
		obj1,
		obj2,
	)
	check(err)
	return r

}

// returns a STIX external reference
func createExternalReference(name string, desc string, url string, externalId string) *stix2.ExternalReference {

	ext, err := stix2.NewExternalReference(
		name,
		desc,
		url,
		externalId,
		nil,
	)
	check(err)
	return ext
}

// creates an indicator object and returns it
func createIndicator(identityRef id) *stix2.Indicator {

	timestamp := stix2.Timestamp{
		Time: time.Now(),
	}

	pattern := "[ cowrie-activity:log_line = 'login attempt [']"
	indicator, err := stix2.NewIndicator(
		pattern,
		"stix",
		&timestamp,
		stix2.OptionCreatedBy(identityRef),
		stix2.OptionDescription("This log line is generated whenever a threat actor gets baited into a Cowrie honeypot"),
		stix2.OptionTypes([]string{"malicious activity"}),
		stix2.OptionName("SSH Brute force access"),
	)
	check(err)

	return indicator

}

// returns a new STIX identity
func createIdentity(name string, class string) *stix2.Identity {

	cyberIdentity, err := stix2.NewIdentity(
		name,
		stix2.OptionClass(class),
	)
	check(err)
	return cyberIdentity
}

func createAttackPattern(name string, desc string, killchain []*stix2.KillChainPhase, extRef []*stix2.ExternalReference) *stix2.AttackPattern {

	a, err := stix2.NewAttackPattern(
		name,
		stix2.OptionDescription(desc),
		stix2.OptionKillChainPhase(killchain),
		stix2.OptionExternalReferences(extRef),
	)
	check(err)
	return a
}

// returns a STIX infrastructure object that can be used to describe any system
func createInfrastructure(name string, desc string, types *[]string, aliases *[]string, killchain []*stix2.KillChainPhase) *stix2.Infrastructure {

	i, err := stix2.NewInfrastructure(
		name,
		stix2.OptionDescription(desc),
		stix2.OptionTypes(*types),
		stix2.OptionAliases(*aliases),
		stix2.OptionKillChainPhase(killchain),
	)
	check(err)
	return i

}

// makes sure the base files, identity, attack-pattern etc...) exist
func CreateBaseFiles(done chan<- bool) {

	var c *stix2.Collection = stix2.New()

	cyberIdentity := createIdentity("cyber team", "team")
	c.Add(cyberIdentity)

	honeypots := createInfrastructure(
		"Cyber team cowrie honeypots",
		"A group of cowrie honeypots (medium interaction) used to detect SSH brute force attacks and shell interactions performed by attackers.",
		&[]string{"hosting-target-lists"},
		&[]string{},
		[]*stix2.KillChainPhase{},
	)
	c.Add(honeypots)

	killChain, err := stix2.NewKillChainPhase("cyber-kill-chain", "exploit")
	check(err)

	externalReference := createExternalReference(
		"capec",
		`An adversary tries every possible value for a password until they succeed.
		 A brute force attack, if feasible computationally, will always be successful because it will essentially go through all possible passwords given 
		 the alphabet used (lower case letters, upper case letters, numbers, symbols, etc.) and the maximum length of the password.`,
		"https://capec.mitre.org/data/definitions/49.html",
		"CAPEC-49",
	)

	sshAttackPattern := createAttackPattern(
		"SSH brute force password guessing",
		"Threat actor tries to guess SSH passwords to attempt access to accounts with an iterative mechanism",
		[]*stix2.KillChainPhase{killChain},
		[]*stix2.ExternalReference{externalReference},
	)
	c.Add(sshAttackPattern)

	cowrieIndicator := createIndicator(cyberIdentity.GetID())
	c.Add(cowrieIndicator)

	r := createRelationship(cowrieIndicator.GetID(), sshAttackPattern.GetID(), stix2.RelationshipTypeIndicates)
	c.Add(r)

	b, err := c.ToBundle()
	check(err)

	storeObject(cyberIdentity)
	storeBundle(b)
	done <- true

}

// writes STIX object to file, the file will be named <id>.json
func storeObject(obj stix2.STIXObject) {
	data, err := json.MarshalIndent(obj, "", "\t")
	check(err)
	objId := string(obj.GetID())
	writeJsonToFile(data, objId)
}

func storeBundle(bundle *stix2.Bundle) {
	data, err := json.MarshalIndent(bundle, "", "\t")
	check(err)
	id := string(bundle.ID)
	writeJsonToFile(data, id)

}

func writeJsonToFile(data []byte, objId string) error {

	err := os.WriteFile(StixDir+objId+".json", data, 0664)
	check(err)

	return nil
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
