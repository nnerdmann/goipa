package ipa

import (
	"encoding/json"
	"testing"
)

func TestUserIndirectGroupsFromJSON(t *testing.T) {
	raw := []byte(`{"uid":["ada"],"memberof_group":["lab-users"],"memberofindirect_group":["unix-access"]}`)
	var user User
	if err := user.fromJSON(raw); err != nil {
		t.Fatal(err)
	}
	if len(user.Groups) != 1 || user.Groups[0] != "lab-users" {
		t.Fatalf("groups = %#v", user.Groups)
	}
	if len(user.IndirectGroups) != 1 || user.IndirectGroups[0] != "unix-access" {
		t.Fatalf("indirect groups = %#v", user.IndirectGroups)
	}
}

func TestHbacRuleDecode(t *testing.T) {
	raw := []byte(`[
		{"cn":["ssh-lab"],"ipaenabledflag":[true],"memberuser_group":["lab-users"],"memberhost_hostgroup":["lab"],"memberservice_hbacsvc":["sshd"]},
		{"cn":["old"],"ipaenabledflag":["FALSE"],"usercategory":["all"],"hostcategory":["all"]},
		{"cn":["noflag"]}
	]`)
	var rules []*HbacRule
	if err := unmarshalList(raw, &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("rules = %d", len(rules))
	}
	if rules[0].Name() != "ssh-lab" || !rules[0].Enabled() || rules[0].MemberHostGroups[0] != "lab" {
		t.Fatalf("rule 0 = %#v", rules[0])
	}
	if rules[1].Enabled() || !rules[1].AllUsers() || !rules[1].AllHosts() {
		t.Fatalf("rule 1 = %#v", rules[1])
	}
	if !rules[2].Enabled() {
		t.Fatal("a rule without ipaenabledflag counts as enabled")
	}
}

func TestSudoRuleAndHostGroupDecode(t *testing.T) {
	var rule SudoRule
	if err := json.Unmarshal([]byte(`{"cn":["admins-sudo"],"ipaenabledflag":["TRUE"],"cmdcategory":["all"],"memberuser_group":["ops"]}`), &rule); err != nil {
		t.Fatal(err)
	}
	if !rule.Enabled() || !rule.AllCommands() || rule.MemberGroups[0] != "ops" {
		t.Fatalf("sudo rule = %#v", rule)
	}

	var group HostGroupRecord
	if err := json.Unmarshal([]byte(`{"cn":["lab"],"member_host":["a.example"],"memberindirect_host":["b.example"]}`), &group); err != nil {
		t.Fatal(err)
	}
	if group.Name() != "lab" || group.Hosts[0] != "a.example" || group.IndirectHosts[0] != "b.example" {
		t.Fatalf("host group = %#v", group)
	}
}
