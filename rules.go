package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type dnatRule struct {
	num                    int
	name                   string
	enabled                bool
	srcZone, destZone      string
	srcPortLo, srcPortHi   int
	destIp                 string
	destPortLo, destPortHi int
	protos                 []string
}

func (rule *dnatRule) String() string {
	var srcPorts, destPorts, protos string
	if rule.srcPortLo == rule.srcPortHi {
		srcPorts = strconv.Itoa(rule.srcPortLo)
	} else {
		srcPorts = fmt.Sprintf("%d-%d", rule.srcPortLo, rule.srcPortHi)
	}

	if rule.destPortLo == rule.destPortHi {
		destPorts = strconv.Itoa(rule.destPortLo)
	} else {
		destPorts = fmt.Sprintf("%d-%d", rule.destPortLo, rule.destPortHi)
	}

	protos = strings.Join(rule.protos, ",")
	status := ' '
	if rule.enabled {
		status = 'X'
	}

	return fmt.Sprintf("[%c] %02d: %-40s %s{%s}->%s:%s{%s} [%s]", status, rule.num, rule.name, srcPorts, rule.srcZone, rule.destIp, destPorts, rule.destZone, protos)
}

func parseUCIPortRange(rawValue string) (lo, hi int, err error) {
	loHi := strings.Split(rawValue, "-")
	switch len(loHi) {
	case 1:
		lo, err = strconv.Atoi(loHi[0])
		return lo, lo, err
	case 2:
		lo, err = strconv.Atoi(loHi[0])
		if err != nil {
			return 0, 0, err
		}
		hi, err = strconv.Atoi(loHi[1])
		if err != nil {
			return 0, 0, err
		}
		return lo, hi, err
	default:
		return 0, 0, fmt.Errorf("Invalid port-range '%s'", rawValue)
	}
}

func parseUCIValues(rawValue string) ([]string, error) {
	// UCI values are given in single-quotes with backslashes escaping nested
	// single quotes. Multiple values are given with a chosen delimiter (space
	// by default) between quoted values. At least this is what the *file*
	// permits according to
	// https://openwrt.org/docs/guide-user/base-system/uci#file_syntax
	//
	// The command-line syntax outputs values that look like sh syntax. So a
	// name that contains a prefix P, a suffix S, and a single-quote between
	// looks like:
	//
	//   $ uci show 'firewall.@redirect[0].name'
	//   firewall.cfg123.name='P'\''S'
	//
	// Note that P or S (or both) can be blank.
	values := make([]string, 0, 2)
	value := make([]rune, 0, 64)

	const (
		stateUnquoted = iota
		stateInQuote
		stateCloseQuote
		stateBackslash
		stateBackslashQuote
	)

	state := stateUnquoted
	for i, ch := range rawValue {
		switch state {
		case stateUnquoted:
			if ch == '\'' {
				state = stateInQuote
				value = value[:0]
			}
		case stateInQuote:
			if ch == '\'' {
				state = stateCloseQuote
			} else {
				value = append(value, ch)
			}
		case stateCloseQuote:
			if ch == ' ' {
				state = stateUnquoted
				values = append(values, string(value))
			} else if ch == '\\' {
				state = stateBackslash
			} else {
				return nil, fmt.Errorf("UCI value has unexpected unquoted character '%c' (at %d): %s", ch, i+1, rawValue)
			}
		case stateBackslash:
			if ch != '\'' {
				return nil, fmt.Errorf("UCI value has unexpected escaped character '%c' (at %d): %s", ch, i+1, rawValue)
			}
			state = stateBackslashQuote
			value = append(value, '\'')
		case stateBackslashQuote:
			if ch != '\'' {
				return nil, fmt.Errorf("UCI value has unexpected post-escape character '%c' (at %d): %s", ch, i+1, rawValue)
			}
			state = stateInQuote
		}
	}
	if state == stateCloseQuote {
		values = append(values, string(value))
	}
	return values, nil
}

func parseUCIDNATRules(rdr io.Reader) ([]*dnatRule, error) {
	// See https://openwrt.org/docs/guide-user/base-system/uci and
	// https://openwrt.org/docs/guide-user/firewall/firewall_configuration#options4
	rules := make([]*dnatRule, 0, 16)
	var currentRule *dnatRule

	lineRdr := bufio.NewReader(rdr)
	eof := false
	for !eof {
		line, err := lineRdr.ReadString('\n')
		if errors.Is(err, io.EOF) {
			eof = true
		} else if err != nil {
			return nil, err
		}

		line = strings.TrimSuffix(line, "\n")
		if len(line) == 0 {
			continue
		}

		// Rules are either 'config.section=type', 'config.@section[idx]=type', 'config.@section'
		// Rules take one of a few formats:
		//   config.section=type
		//   config.@section[idx]=type
		//   config.section.field='value'( 'value')*
		//   config.@section[idx].field='value'( 'value')*
		//
		// For both the '=' and the '.' in keys, a simple split is safe because keys cannot contain
		// '=' and neither the config, section, index, or field can contain '.'
		//
		// We're reporting all rules in the 'firewall.@redirect' section that have the DNAT target.
		keyValue := strings.SplitN(line, "=", 2)
		if len(keyValue) != 2 {
			return nil, fmt.Errorf("UCI config is missing '=': %s", line)
		}

		// A simple split is safe in both
		configSectionField := strings.Split(keyValue[0], ".")
		if len(configSectionField) > 0 && configSectionField[0] != "firewall" {
			continue
		}

		var config, section, indexStr, field string
		indexNum := -1

		switch len(configSectionField) {
		case 2:
			// config.section or config.@section[idx]
			config, section = configSectionField[0], configSectionField[1]
			if strings.HasPrefix(section, "@") {
				indexStart := strings.IndexRune(section, '[')
				if indexStart == -1 || !strings.HasSuffix(section, "]") {
					return nil, fmt.Errorf("UCI key '%s' has '@section' but no '[index]': %s", keyValue[0], section)
				}
				indexStr = section[indexStart+1 : len(section)-1]
				if indexNum, err = strconv.Atoi(indexStr); err != nil {
					return nil, fmt.Errorf("UCI key '%s' has invalid '[index]': %s", keyValue[0], section, indexStr)
				}
				section = section[1:indexStart]
			}

			if config == "firewall" && section == "redirect" && indexNum != -1 {
				if currentRule != nil {
					rules = append(rules, currentRule)
				}
				currentRule = &dnatRule{
					num:     indexNum,
					enabled: true,
				}
			}

		case 3:
			// config.section.field or config.@section[idx].field
			config, section, field = configSectionField[0], configSectionField[1], configSectionField[2]
			if strings.HasPrefix(section, "@") {
				indexStart := strings.IndexRune(section, '[')
				if indexStart == -1 || !strings.HasSuffix(section, "]") {
					return nil, fmt.Errorf("UCI key '%s' has '@section' but no '[index]': %s", keyValue[0], section)
				}
				indexStr = section[indexStart+1 : len(section)-1]
				if indexNum, err = strconv.Atoi(indexStr); err != nil {
					return nil, fmt.Errorf("UCI key '%s' has invalid '[index]': %s", keyValue[0], section, indexStr)
				}
				section = section[1:indexStart]
			}

			if config != "firewall" || section != "redirect" || indexNum == -1 {
				continue
			}
			if currentRule == nil {
				return nil, fmt.Errorf("UCI key '%s' appears before section key 'firewall.@redirect[%d]'", keyValue[0], indexNum)
			}

			values, err := parseUCIValues(keyValue[1])
			if err != nil {
				return nil, fmt.Errorf("In UCI key '%s', %s", keyValue[0], err.Error())
			}

			switch field {
			case "name":
				if len(values) != 1 {
					return nil, fmt.Errorf("UCI key '%s' has invalid name: %s", keyValue[0], keyValue[1])
				}
				currentRule.name = values[0]
			case "src":
				if len(values) != 1 {
					return nil, fmt.Errorf("UCI key '%s' has invalid src: %s", keyValue[0], keyValue[1])
				}
				currentRule.srcZone = values[0]
			case "dest":
				if len(values) != 1 {
					return nil, fmt.Errorf("UCI key '%s' has invalid dest: %s", keyValue[0], keyValue[1])
				}
				currentRule.destZone = values[0]
			case "dest_ip":
				if len(values) != 1 {
					return nil, fmt.Errorf("UCI key '%s' has invalid dest_ip: %s", keyValue[0], keyValue[1])
				}
				currentRule.destIp = values[0]
			case "proto":
				currentRule.protos = values
			case "src_dport":
				if len(values) != 1 {
					return nil, fmt.Errorf("UCI key '%s' has invalid src_dport: %s", keyValue[0], keyValue[1])
				}
				currentRule.srcPortLo, currentRule.srcPortHi, err = parseUCIPortRange(values[0])
				if currentRule.destPortLo == 0 && currentRule.destPortHi == 0 {
					currentRule.destPortLo, currentRule.destPortHi = currentRule.srcPortLo, currentRule.srcPortHi
				}
				if err != nil {
					return nil, fmt.Errorf("UCI key '%s' has invalid src_dport: %s", keyValue[0], err.Error())
				}
			case "dest_port":
				if len(values) != 1 {
					return nil, fmt.Errorf("UCI key '%s' has invalid dest_port: %s", keyValue[0], keyValue[1])
				}
				currentRule.destPortLo, currentRule.destPortHi, err = parseUCIPortRange(values[0])
				if err != nil {
					return nil, fmt.Errorf("UCI key '%s' has invalid dest_port: %s", keyValue[0], err.Error())
				}
			case "enabled":
				if len(values) != 1 {
					return nil, fmt.Errorf("UCI key '%s' has invalid enabled: %s", keyValue[0], keyValue[1])
				}
				currentRule.enabled = values[0] == "1"
			}

		default:
			return nil, fmt.Errorf("UCI key '%s' malformed", keyValue[0])
		}
	}

	if currentRule != nil {
		rules = append(rules, currentRule)
	}
	return rules, nil
}

type ruleMatch interface {
	matchesRule(rule *dnatRule) bool
	String() string
}

type substrNameMatch struct {
	substr string
}

func (match *substrNameMatch) matchesRule(rule *dnatRule) bool {
	return strings.Contains(strings.ToLower(rule.name), match.substr)
}

func (match *substrNameMatch) String() string {
	return match.substr
}

type exactNameMatch struct {
	exact string
}

func (match *exactNameMatch) matchesRule(rule *dnatRule) bool {
	return rule.name == match.exact
}

func (match *exactNameMatch) String() string {
	return match.exact
}

type numericMatch struct {
	num int
}

func (match *numericMatch) matchesRule(rule *dnatRule) bool {
	return rule.num == match.num
}

func (match *numericMatch) String() string {
	return strconv.Itoa(match.num)
}
