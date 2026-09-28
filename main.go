package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/pborman/getopt/v2"
)

func detailedUsage() {
	fmt.Printf("Usage: %s [-h|--help] (-x|--exact|-n|--numeric)? (-s|--server) SERVER (-u|--user) USER [-p|--port] PORT SUBCOMMAND...", os.Args[0])
	fmt.Println(`Subcommands:
  help: Displays this message.
  list: Displays all DNAT firewall rules. The default subcommand if none is given.
  enable NAME...: Enables listed firewall rules and restarts the firewall.
  disable NAME...: Disables listed firewall rules and restarts the firewall.

Subcommand options:
  NAME: The name of a firewall rule. By default this is a case-insensitive
        substring match. When -x|--exact is provided, this is instead a
        case-sensitive exact match. When -n|--numeric is provided, this
        is the rule's position in the firwall list (counting up from 0).
        Providing -x|--exact or -n|--numeric affects how *all* NAME values
        are interpreted.

        If a name matches multiple rules (which is possible even with exact
        matching, since OpenWRT does not force rule names to be unique) or
        does not match any rule, then the entire command aborts.
`)
}

func buildMatchers(exactFmt bool, numericFmt bool, args []string) ([]ruleMatch, error) {
	matchers := make([]ruleMatch, len(args))
	for i, arg := range args {
		if exactFmt {
			matchers[i] = &exactNameMatch{exact: arg}
		} else if numericFmt {
			num, err := strconv.Atoi(arg)
			if err != nil || num < 0 {
				return nil, fmt.Errorf("Invalid rule number '%s'", arg)
			}
			matchers[i] = &numericMatch{num: num}
		} else {
			if len(arg) == 0 {
				return nil, fmt.Errorf("Substring pattern cannot be empty")
			}
			matchers[i] = &substrNameMatch{substr: strings.ToLower(arg)}
		}
	}
	return matchers, nil
}

func main() {
	helpFlag := getopt.BoolLong("--help", 'h', "Displays this help")
	getopt.Lookup('h').SetOptional()

	serverFlag := getopt.StringLong("--server", 's', "", "The hostname or IP of the OpenWRT server", "myrouter.local")
	getopt.Lookup('s').Mandatory()

	portFlag := getopt.IntLong("--port", 'p', 22, "The port that SSH is running at on the server", "22")
	getopt.Lookup('p').SetOptional()

	userFlag := getopt.StringLong("--user", 'u', "", "The username to use when conencting via SSH", "root")
	getopt.Lookup('u').Mandatory()

	exactFmtFlag := getopt.BoolLong("--exact", 'x', "Use exact matching for rule names.")
	getopt.Lookup('x').SetOptional().SetGroup("name-format")

	numericFmtFlag := getopt.BoolLong("--numeric", 'n', "Use rule numbers instead of rule names.")
	getopt.Lookup('n').SetOptional().SetGroup("name-format")

	getopt.Parse()
	if *helpFlag {
		detailedUsage()
		getopt.Usage()
		os.Exit(1)
	}

	subcommand := getopt.Args()
	if len(subcommand) == 0 || subcommand[0] == "help" {
		detailedUsage()
		getopt.Usage()
		os.Exit(1)
	}

	if *serverFlag == "" {
		fmt.Println("SSH server is required")
		getopt.Usage()
		os.Exit(1)
	}

	if *userFlag == "" {
		fmt.Println("SSH user is required")
		getopt.Usage()
		os.Exit(1)
	}

	if *portFlag <= 0 || *portFlag > math.MaxUint16 {
		fmt.Printf("Invalid port: %d", *portFlag)
		os.Exit(1)
	}

	var matchers []ruleMatch
	var err error
	switch subcommand[0] {
	case "list":
		doListAction(*serverFlag, *portFlag, *userFlag)
	case "enable":
		matchers, err = buildMatchers(*exactFmtFlag, *numericFmtFlag, subcommand[1:])
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		doEnableAction(*serverFlag, *portFlag, *userFlag, matchers)
	case "disable":
		matchers, err = buildMatchers(*exactFmtFlag, *numericFmtFlag, subcommand[1:])
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		doDisableAction(*serverFlag, *portFlag, *userFlag, matchers)
	default:
		fmt.Printf("Unknown subcommand %s", subcommand[0])
		getopt.Usage()
		os.Exit(1)
	}
}
