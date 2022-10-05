# carrots: in situ permission scanner

# EXAMPLES

```console
$ cd examples

$ carrots
/Users/andrew/go/src/github.com/mcandre/carrots/examples/.ssh: expected chmod 0700, got 0755
/Users/andrew/go/src/github.com/mcandre/carrots/examples/.ssh/authorized_keys: expected chmod 0600, got 0644
```

# ABOUT

carrots scans file paths for permission discrepancies. For example, SSH requires files and directories to adhere to a standard chmod permission bit policy. When carrots detects a discrepancy, it emits a warning.

🥕
