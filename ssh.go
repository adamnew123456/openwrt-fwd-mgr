package main

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func openSSHConnection(server string, port int, user string) (*ssh.Client, error) {
	agentSocket := os.Getenv("SSH_AUTH_SOCK")
	if len(agentSocket) == 0 {
		return nil, fmt.Errorf("An SSH agent is required, but SSH_AUTH_SOCK is not set")
	}

	agentConn, err := net.Dial("unix", agentSocket)
	if err != nil {
		return nil, fmt.Errorf("Error accessing SSH agent: %s", err.Error())
	}

	agentClient := agent.NewClient(agentConn)
	sshConfig := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", server, port), &sshConfig)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to SSH server: %s", err.Error())
	}

	return sshClient, nil
}

func runShellCommand(client *ssh.Client, command string) (stdout, stderr []byte, err error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("Could not open shell session: %s", err.Error())
	}
	defer session.Close()

	var outBuf, errBuf bytes.Buffer
	session.Stdout = &outBuf
	session.Stderr = &errBuf
	fmt.Printf("$ %s\n", command)
	err = session.Run(command)
	if err != nil {
		return outBuf.Bytes(), errBuf.Bytes(), fmt.Errorf("Error running command: %s\n", err.Error())
	} else {
		return outBuf.Bytes(), errBuf.Bytes(), nil
	}
}

func listUCIFirewallRules(client *ssh.Client) ([]*dnatRule, error) {
	stdout, stderr, err := runShellCommand(client, "uci show firewall")
	if err != nil {
		if stderr != nil && len(stderr) > 0 {
			fmt.Printf("Received UCI error: %s\n", string(stderr))
		}
		return nil, err
	}

	return parseUCIDNATRules(bytes.NewReader(stdout))
}

func toggleUCIFirewallRules(client *ssh.Client, rules []*dnatRule, enable bool) error {
	var status int
	if enable {
		status = 1
	}

	var err error
	for _, rule := range rules {
		command := fmt.Sprintf("uci set 'firewall.@redirect[%d].enabled=%d'", rule.num, status)
		if _, stderr, err := runShellCommand(client, command); err != nil {
			revertUCIFirewallRules(client)
			if stderr != nil && len(stderr) > 0 {
				fmt.Printf("Received UCI error: %s\n", string(stderr))
			}
			return err
		}
	}

	if err = commitUCIFirewallRules(client); err != nil {
		revertUCIFirewallRules(client)
		return err
	}

	restartFirewallService(client)
	return nil
}

func commitUCIFirewallRules(client *ssh.Client) error {
	_, stderr, err := runShellCommand(client, "uci commit firewall")
	if err != nil {
		if stderr != nil && len(stderr) > 0 {
			fmt.Printf("Received UCI error: %s\n", string(stderr))
		}
		return err
	}
	return nil
}

// Neither restarting the firewall nor reverting the firewall rules can
// meaningfully fail:
//
// - Restarting the firewall service happens after the new rules are
//   committed. We can't undo the rules at that point without risking
//   more errors, let the operator know to restart the service by hand.
//
// - Reverting the firewall rules leaves the pending rule changes
//   in an unknown state. UCI may be broken which again requires operator
//   intervention.

func restartFirewallService(client *ssh.Client) {
	_, stderr, err := runShellCommand(client, "service firewall restart")
	if err != nil {
		if stderr != nil && len(stderr) > 0 {
			fmt.Printf("Received UCI error: %s\n", string(stderr))
		}
		fmt.Println(`
Firewall rules committed but not in effect. Restart the firewall service by hand
and diagnose any issues.`)
	}
}

func revertUCIFirewallRules(client *ssh.Client) {
	_, stderr, err := runShellCommand(client, "uci revert firewall")
	if err != nil {
		if stderr != nil && len(stderr) > 0 {
			fmt.Printf("Received UCI error: %s\n", string(stderr))
		}
		fmt.Printf("Unable to revert firewall rules: %s\n", err.Error())
		fmt.Println(`
UCI has pending firewall config changes that could not be applied. Review them
using the 'uci' command line tool and revert/apply by hand as necessary.
`)
	}
}

func filterRules(rules []*dnatRule, matchers []ruleMatch) ([]*dnatRule, error) {
	matchRules := make([]*dnatRule, 0, len(rules))
	for _, matcher := range matchers {
		candidate := -1
		for i, rule := range rules {
			if rule == nil {
				continue
			}
			if matcher.matchesRule(rule) {
				if candidate == -1 {
					candidate = i
				} else {
					return nil, fmt.Errorf("Pattern %s matches multiple rules:\n- %s\n- %s\n", matcher.String(), rules[candidate], rule)
				}
			}
		}

		if candidate == -1 {
			return nil, fmt.Errorf("Pattern %s matches no rules", matcher.String())
		}

		matchRules = append(matchRules, rules[candidate])
		rules[candidate] = nil
	}
	return matchRules, nil
}

func doListAction(server string, port int, user string) {
	connect, err := openSSHConnection(server, port, user)
	if err != nil {
		fmt.Printf("SSH error, %s\n", err.Error())
		os.Exit(1)
	}
	defer connect.Close()

	rules, err := listUCIFirewallRules(connect)
	if err != nil {
		fmt.Printf("UCI error, %s\n", err.Error())
		os.Exit(1)
	}

	for _, rule := range rules {
		fmt.Println(rule.String())
	}
}

func doEnableAction(server string, port int, user string, matchers []ruleMatch) {
	client, err := openSSHConnection(server, port, user)
	if err != nil {
		fmt.Printf("SSH error, %s\n", err.Error())
		os.Exit(1)
	}
	defer client.Close()

	rules, err := listUCIFirewallRules(client)
	if err != nil {
		fmt.Printf("UCI error, %s\n", err.Error())
		os.Exit(1)
	}

	matchRules, err := filterRules(rules, matchers)
	if err != nil {
		fmt.Printf("Match error, %s\n", err.Error())
		os.Exit(1)
	}

	err = toggleUCIFirewallRules(client, matchRules, true)
	if err != nil {
		fmt.Printf("Firewall error, %s\n", err.Error())
		os.Exit(1)
	}
}

func doDisableAction(server string, port int, user string, matchers []ruleMatch) {
	client, err := openSSHConnection(server, port, user)
	if err != nil {
		fmt.Printf("SSH error, %s\n", err.Error())
		os.Exit(1)
	}
	defer client.Close()

	rules, err := listUCIFirewallRules(client)
	if err != nil {
		fmt.Printf("UCI error, %s\n", err.Error())
		os.Exit(1)
	}

	matchRules, err := filterRules(rules, matchers)
	if err != nil {
		fmt.Printf("Match error, %s\n", err.Error())
		os.Exit(1)
	}

	err = toggleUCIFirewallRules(client, matchRules, false)
	if err != nil {
		fmt.Printf("Firewall error, %s\n", err.Error())
		os.Exit(1)
	}
}
