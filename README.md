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
.ssh/id_test: expected chmod 0600, got 0644
```

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

To analyze specific paths, list some files and/or directories explicitly. For example, to scan your live SSH directory tree:

```console
$ sunshine ~/.ssh
```

By default, `sunshine` analyzes the current working directory tree.

# SEE ALSO

* [chmod](https://linux.die.net/man/1/chmod) alters file permissions
* [file](https://linux.die.net/man/1/file) analyzes file types
* [ls](https://linux.die.net/man/1/ls) can list file permissions
* [stank](https://github.com/mcandre/stank) analyzes executable and library shell scripts
