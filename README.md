# sunshine: file permission security analyzer

![a regal sun rising upon the beach](sunshine.jpg)

# ABOUT

> sunshine is the best disinfectant

`sunshine` reveals paths with anomalous file permissions.

File permissions play a critical role in software applications, from security to basic functionality. For example, SSH may reject authentication attempts when the keys have incorrect permissions.

Unfortunately, many software systems have neither the correct file permissions applied, nor useful error handling code to help users quickly diagnose the issue. That's where sunshine comes up.

sunshine is an automated program for recursively scanning files and directories for unidiomatic permission settings.

# EXAMPLE

```console
$ cd examples

$ sunshine
2022/10/06 12:54:43 warning: /Users/andrew/go/src/github.com/mcandre/sunshine/examples/.ssh/id_test: expected chmod 0600, got 0644
```

See `-help` for more detail.

# DOCUMENTATION

https://pkg.go.dev/github.com/mcandre/sunshine

# DOWNLOAD

https://github.com/mcandre/sunshine/releases

# INSTALL FROM SOURCE

```console
$ go install github.com/mcandre/sunshine/cmd/sunshine@latest
```

# RUNTIME REQUIREMENTS

None

# CONTRIBUTING

For more information on developing tug itself, see [DEVELOPMENT.md](DEVELOPMENT.md).

# LICENSE

BSD-2-Clause

# USAGE

sunshine follows classical UNIX CLI conventions: Basic exit codes, and no output except in case of an issue.

By default, sunshine analyzes the current working directory tree. To analyze specific paths, list some files and/or directories explicitly.

To scan the example SSH keys:

```console
$ sunshine .ssh/id_test .ssh/id_test.pub
2022/10/06 12:55:01 warning: .ssh/id_test: expected chmod 0600, got 0644
```

To scan your live SSH directory tree:

```console
$ sunshine ~/.ssh
```

# SEE ALSO

* [brew](https://brew.sh/) package manager provides a self permission check with the `brew doctor` command
* [chmod](https://linux.die.net/man/1/chmod) alters file permissions
* [file](https://linux.die.net/man/1/file) analyzes file types
* [ls](https://linux.die.net/man/1/ls) can list file permissions
* [stank](https://github.com/mcandre/stank) analyzes executable and library shell scripts
