package main

import (
	"flag"
	"fmt"
	"io"
)

// completeArgs walks command name -> op (command.sub) -> op's flags
// (command.opBodies) -> nested op's flags (command.nested), reading the
// exact bodies/factories real dispatch (opDispatch) runs through.
func completeArgs(words []string) []string {
	find := func(name string) *command {
		for i := range commands {
			if commands[i].name == name || commands[i].alias == name {
				return &commands[i]
			}
		}
		return nil
	}

	gfs := flag.NewFlagSet("ovcp", flag.ContinueOnError)
	gfs.SetOutput(io.Discard)
	globalFlags(gfs)
	if gfs.Parse(words[1:]) != nil {
		return nil
	}
	rest := gfs.Args() // words after "ovcp" with any global flags stripped

	switch {
	case len(rest) == 0:
		names := make([]string, len(commands))
		for i, c := range commands {
			names[i] = c.name
		}
		gfs.VisitAll(func(f *flag.Flag) { names = append(names, "-"+f.Name) })
		return names
	case len(rest) == 1:
		c := find(rest[0])
		if c == nil {
			return nil
		}
		if c.sub != nil {
			return c.sub
		}
		return c.flagNames()
	default:
		// rest[1] is the op; a further-nested op (only "config" today) drills
		// one level deeper into its own ops/flags, same data opDispatch
		// itself runs on for real execution — nothing hardcoded here.
		c := find(rest[0])
		if c == nil {
			return nil
		}
		op := rest[1]
		if nd, ok := c.nested[op]; ok {
			if len(rest) == 2 {
				return nd.ops
			}
			return opBodiesFlagNames(nd.bodies, rest[2])
		}
		return opBodiesFlagNames(c.opBodies, op)
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

// The stubs below just forward the command line to `ovcp __complete`, which
// reads commands.go's table, so they never change. Regenerate via `ovcp completion <shell>`, not by hand.

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
