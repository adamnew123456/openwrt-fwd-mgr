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

func listUCIFirewallRules(client *ssh.Client) ([]*dnatRule, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("Could not open shell session: %s", err.Error())
	}
	defer session.Close()

	var outBuf, errBuf bytes.Buffer
	session.Stdout = &outBuf
	session.Stderr = &errBuf
	err = session.Run(fmt.Sprintf("uci show firewall"))
	if err != nil {
		if errBuf.Len() > 0 {
			fmt.Printf("Received UCI error: %s\n", string(errBuf.Bytes()))
		}
		return nil, fmt.Errorf("Error running `uci show firewall`: %s\n", err.Error())
	}

	return parseUCIDNATRules(bytes.NewReader(outBuf.Bytes()))
}

func toggleUCIFirewallRules(client *ssh.Client, rules []*dnatRule, enable bool) error {
	var status int
	if enable {
		status = 1
	}

	var err error
	var outBuf, errBuf bytes.Buffer
	for _, rule := range rules {
		(func() {
			session, err := client.NewSession()
			if err != nil {
				err = fmt.Errorf("Could not open shell session: %s", err.Error())
			}
			defer session.Close()

			outBuf.Reset()
			errBuf.Reset()
			session.Stdout = &outBuf
			session.Stderr = &errBuf

			command := fmt.Sprintf("uci set 'firewall.@redirect[%d].enabled=%d'", rule.num, status)
			fmt.Printf("$ %s\n", command)
			err = session.Run(command)
			if err != nil {
				revertUCIFirewallRules(client)

				if errBuf.Len() > 0 {
					fmt.Printf("Received UCI error: %s\n", string(errBuf.Bytes()))
				}
				err = fmt.Errorf("Error running `%s`: %s\n", command, err.Error())
			}
		})()
	}

	errBuf.Reset()
	err = commitUCIFirewallRules(client)
	if err != nil {
		revertUCIFirewallRules(client)
		return err
	}

	return nil
}

func commitUCIFirewallRules(client *ssh.Client) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Could not open shell session: %s", err.Error())
	}
	defer session.Close()

	var errBuf bytes.Buffer
	session.Stderr = &errBuf
	fmt.Println("$ uci commit firewall")
	err = session.Run("uci commit firewall")
	if err != nil {
		if errBuf.Len() > 0 {
			fmt.Printf("Received UCI error: %s\n", string(errBuf.Bytes()))
		}
		return fmt.Errorf("Error running `uci commit firewall`: %s\n", err.Error())
	}
	return nil
}

func revertUCIFirewallRules(client *ssh.Client) {
	session, err := client.NewSession()
	if err != nil {
		return
	}

	defer session.Close()
	fmt.Println("$ uci revert firewall")
	session.Run("uci revert firewall")
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
