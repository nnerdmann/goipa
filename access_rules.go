package ipa

import (
	"encoding/json"
	"errors"
	"strings"
)

// HbacRule is a FreeIPA host-based access control rule.
type HbacRule struct {
	Cn               []string `json:"cn"`
	EnabledFlag      IpaBool  `json:"ipaenabledflag"`
	UserCategory     []string `json:"usercategory"`
	HostCategory     []string `json:"hostcategory"`
	ServiceCategory  []string `json:"servicecategory"`
	MemberUsers      []string `json:"memberuser_user"`
	MemberGroups     []string `json:"memberuser_group"`
	MemberHosts      []string `json:"memberhost_host"`
	MemberHostGroups []string `json:"memberhost_hostgroup"`
	Services         []string `json:"memberservice_hbacsvc"`
	ServiceGroups    []string `json:"memberservice_hbacsvcgroup"`
}

// SudoRule is a FreeIPA sudo rule.
type SudoRule struct {
	Cn                   []string `json:"cn"`
	EnabledFlag          IpaBool  `json:"ipaenabledflag"`
	UserCategory         []string `json:"usercategory"`
	HostCategory         []string `json:"hostcategory"`
	CommandCategory      []string `json:"cmdcategory"`
	MemberUsers          []string `json:"memberuser_user"`
	MemberGroups         []string `json:"memberuser_group"`
	MemberHosts          []string `json:"memberhost_host"`
	MemberHostGroups     []string `json:"memberhost_hostgroup"`
	AllowedCommands      []string `json:"memberallowcmd_sudocmd"`
	AllowedCommandGroups []string `json:"memberallowcmd_sudocmdgroup"`
}

// HostGroupRecord is a FreeIPA host group with direct and nested member hosts.
type HostGroupRecord struct {
	Cn            []string `json:"cn"`
	Hosts         []string `json:"member_host"`
	IndirectHosts []string `json:"memberindirect_host"`
	HostGroups    []string `json:"member_hostgroup"`
}

// Name returns the rule name.
func (r *HbacRule) Name() string { return firstValue(r.Cn) }

// Enabled reports whether the rule is active. A missing flag counts as enabled.
func (r *HbacRule) Enabled() bool { return enabledFlag(r.EnabledFlag) }

// AllUsers reports whether the rule applies to every user.
func (r *HbacRule) AllUsers() bool { return categoryAll(r.UserCategory) }

// AllHosts reports whether the rule applies to every host.
func (r *HbacRule) AllHosts() bool { return categoryAll(r.HostCategory) }

// AllServices reports whether the rule allows every HBAC service.
func (r *HbacRule) AllServices() bool { return categoryAll(r.ServiceCategory) }

// Name returns the rule name.
func (r *SudoRule) Name() string { return firstValue(r.Cn) }

// Enabled reports whether the rule is active. A missing flag counts as enabled.
func (r *SudoRule) Enabled() bool { return enabledFlag(r.EnabledFlag) }

// AllUsers reports whether the rule applies to every user.
func (r *SudoRule) AllUsers() bool { return categoryAll(r.UserCategory) }

// AllHosts reports whether the rule applies to every host.
func (r *SudoRule) AllHosts() bool { return categoryAll(r.HostCategory) }

// AllCommands reports whether the rule allows every command.
func (r *SudoRule) AllCommands() bool { return categoryAll(r.CommandCategory) }

// Name returns the host group name.
func (g *HostGroupRecord) Name() string { return firstValue(g.Cn) }

// HbacRuleFind returns all HBAC rules with their members.
func (c *Client) HbacRuleFind() ([]*HbacRule, error) {
	var rules []*HbacRule
	err := c.findList("hbacrule_find", &rules)
	return rules, err
}

// SudoRuleFind returns all sudo rules with their members.
func (c *Client) SudoRuleFind() ([]*SudoRule, error) {
	var rules []*SudoRule
	err := c.findList("sudorule_find", &rules)
	return rules, err
}

// HostGroupFind returns all host groups with direct and nested member hosts.
func (c *Client) HostGroupFind() ([]*HostGroupRecord, error) {
	var groups []*HostGroupRecord
	err := c.findList("hostgroup_find", &groups)
	return groups, err
}

// HostGroupShow returns one host group with direct and nested member hosts.
func (c *Client) HostGroupShow(cn string) (*HostGroupRecord, error) {
	res, err := c.rpc("hostgroup_show", []string{cn}, Options{
		"all":        true,
		"no_members": false,
	})
	if err != nil {
		return nil, err
	}
	if res.Result == nil {
		return nil, errors.New("empty host group response")
	}

	group := new(HostGroupRecord)
	if err := json.Unmarshal(res.Result.Data, group); err != nil {
		return nil, err
	}
	return group, nil
}

func (c *Client) findList(method string, dest interface{}) error {
	res, err := c.rpc(method, []string{""}, Options{
		"all":        true,
		"no_members": false,
		"sizelimit":  0,
	})
	if err != nil {
		return err
	}
	if res.Result == nil {
		return errors.New("empty " + method + " response")
	}
	return unmarshalList(res.Result.Data, dest)
}

func unmarshalList(raw json.RawMessage, dest interface{}) error {
	if s := strings.TrimSpace(string(raw)); s == "" || s == "null" {
		return nil
	}
	return json.Unmarshal(raw, dest)
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func categoryAll(values []string) bool {
	for _, v := range values {
		if strings.EqualFold(v, "all") {
			return true
		}
	}
	return false
}

// IpaBool decodes FreeIPA boolean attributes. Servers return either [true] or ["TRUE"].
// Set is false when the attribute was absent.
type IpaBool struct {
	Value bool
	Set   bool
}

// UnmarshalJSON accepts a bool, a string, or a single-element list of either.
func (b *IpaBool) UnmarshalJSON(raw []byte) error {
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err == nil {
		if len(list) == 0 {
			return nil
		}
		raw = list[0]
	}

	var v bool
	if err := json.Unmarshal(raw, &v); err == nil {
		b.Value, b.Set = v, true
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	b.Value = strings.EqualFold(s, "true") || s == "1"
	b.Set = true
	return nil
}

func enabledFlag(flag IpaBool) bool {
	return !flag.Set || flag.Value
}
