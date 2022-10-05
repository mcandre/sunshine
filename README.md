# carrots: in situ permission scanner

# EXAMPLES

```console
$ cd examples

$ carrots
.ssh/id_test: expected chmod 0600, got 0644
```

# ABOUT

carrots scans file paths for permission discrepancies. For example, SSH requires files and directories to adhere to a standard chmod permission bit policy. When carrots detects a discrepancy, it emits a warning.

# INSTALL FROM SOURCE

```console
$ go install github.com/mcandre/carrots/cmd/carrots@latest
```

# RUNTIME REQUIREMENTS

None

# CONTRIBUTING

For more information on developing tug itself, see [DEVELOPMENT.md](DEVELOPMENT.md).

# LICENSE

FreeBSD

# USAGE

carrots follows classical UNIX CLI conventions: Basic exit codes, and no output except in case of an issue.

By default, `carrots` analyzes the current working directory tree. To analyze other paths, list some files and/or directories explicitly. For example, to scan your live SSH directory tree:

```console
$ carrots ~/.ssh
```

🥕
