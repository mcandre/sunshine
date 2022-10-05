# carrots: in situ permission scanner

# EXAMPLES

```console
$ cd examples

$ carrots
/Users/andrew/go/src/github.com/mcandre/carrots/examples/.ssh/id_test: expected chmod 0600, got 0644
```

# ABOUT

carrots scans file paths for permission discrepancies. For example, SSH requires files and directories to adhere to a standard chmod permission bit policy. When carrots detects a discrepancy, it emits a warning.

# INSTALL FROM SOURCE

```console
$ go install github.com/mcandre/carrots/cmd/tug@latest
```

# RUNTIME REQUIREMENTS

None

# CONTRIBUTING

For more information on developing tug itself, see [DEVELOPMENT.md](DEVELOPMENT.md).

# LICENSE

FreeBSD

# USAGE

By default, `carrots` analyzes the current working directory tree. To analyze other paths, list some files and/or directories explicitly:

```console
$ carrots .ssh/id_test .ssh/id_test.pub
.ssh/id_test: expected chmod 0600, got 0644
```

🥕
