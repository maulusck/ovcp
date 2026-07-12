package main

import "fmt"

// completeArgs answers "what comes next" given the words typed so far
// (words[0] is always "ovcp"), by reading the same commands table that
// drives real dispatch and -h — so completion can't drift from what the
// CLI actually accepts.
//
// Commands with a fixed subcommand list (vpn, user, backup, debug,
// completion) complete that list at position 2; everything after is out
// of scope (flags specific to e.g. `user add` vs `user passwd` aren't
// completed — add a nested sub->flags table if that's wanted later).
// Commands without one only take flags, so any position from 2 onward
// offers their flag names, read straight off the command's own FlagSet.
func completeArgs(words []string) []string {
	find := func(name string) *command {
		for i := range commands {
			if commands[i].name == name {
				return &commands[i]
			}
		}
		return nil
	}
	switch {
	case len(words) <= 1:
		names := make([]string, len(commands))
		for i, c := range commands {
			names[i] = c.name
		}
		return names
	case len(words) == 2:
		c := find(words[1])
		if c == nil {
			return nil
		}
		if c.sub != nil {
			return c.sub
		}
		return c.flagNames()
	default:
		c := find(words[1])
		if c == nil || c.sub != nil {
			return nil
		}
		return c.flagNames()
	}
}

func completionScript(shell string) (string, error) {
	switch shell {
	case "bash":
		return bashCompletion, nil
	case "zsh":
		return zshCompletion, nil
	case "fish":
		return fishCompletion, nil
	default:
		return "", fmt.Errorf("usage: ovcp completion bash|zsh|fish")
	}
}

// The stubs below never change when commands/subcommands do — they just
// forward the in-progress command line to `ovcp __complete`, which reads
// the table in commands.go. Regenerate via `ovcp completion <shell>`, not
// by hand.

const bashCompletion = `# ovcp bash completion
_ovcp_complete() {
	local words
	words=$(ovcp __complete "${COMP_WORDS[@]:0:COMP_CWORD}")
	COMPREPLY=($(compgen -W "$words" -- "${COMP_WORDS[COMP_CWORD]}"))
}
complete -F _ovcp_complete ovcp
`

const zshCompletion = `#compdef ovcp
_ovcp() {
	local -a candidates
	candidates=(${(f)"$(ovcp __complete ${words[1,CURRENT-1]})"})
	compadd -a candidates
}
_ovcp
`

const fishCompletion = `function __ovcp_complete
	ovcp __complete (commandline -opc)
end
complete -c ovcp -f -a '(__ovcp_complete)'
`
