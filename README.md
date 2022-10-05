# carrots: in situ permission scanner

# EXAMPLES

```console
$ cd examples

$ carrots
/Users/andrew/go/src/github.com/mcandre/carrots/examples/.ssh/id_test: expected chmod 0600, got 0644
```

# ABOUT

carrots scans file paths for permission discrepancies. For example, SSH requires files and directories to adhere to a standard chmod permission bit policy. When carrots detects a discrepancy, it emits a warning.

🥕
