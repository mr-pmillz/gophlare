## gophlare completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	gophlare completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
gophlare completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --config string   config file default location for viper to look is ~/.config/gophlare/config.yaml
      --configfileset   Used internally by gophlare to check if required args are set with and without configuration file, Do not use this flag...
```

### SEE ALSO

* [gophlare completion](gophlare_completion.md)	 - Generate the autocompletion script for the specified shell

###### Auto generated by spf13/cobra on 2-Jul-2025
