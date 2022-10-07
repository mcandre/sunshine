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
.ssh/id_test: expected chmod 0600, got 0644
```

To scan your live SSH directory tree:

```console
$ sunshine ~/.ssh
```

# BEST PRACTICES

sunshine is most effective for analyzing local file systems, dynamic applications, traditional network file storage directory trees such as rsync / FTP, and server / VM environments. Maxmimum security is achieved by deploying only the bare minimum files necessary for service, using chmod 0500 for directories and chmod 0400 for files, on read-only file system mounts. When access is needed by multiple users, apply the a UNIX group policy. Keep credentials and other sensitive data out of base application directory trees.

For safety and security, we recommend static assets rather than dynamic applications, such as deploying Web packs to a CDN. CDN bucket-wide permissions are ideally managed via reusable, scalable role policies, which are easier to apply and validate than individual file/object permissions. And don't make a CDN bucket world-readable without cause.

Dynamic applications can be compiled as static executables (chmod 0500) and installed into `FROM scratch` Docker containers, with immutable file systems. sunshine may prove useful for underlying hypervisor and Kubernetes node environments, where traditional server security must still be maintained.

Classical SSH access can be disabled entirely in favor of cloud console access (VM's), or in favor of `kubectl exec` access (Kubernetes pods).

# SEE ALSO

* [brew](https://brew.sh/) package manager provides a self permission check with the `brew doctor` command
* [chmod](https://linux.die.net/man/1/chmod) alters file permissions
* [file](https://linux.die.net/man/1/file) analyzes file types
* [find](https://linux.die.net/man/1/find) can identify files and directories with specific permission matches
* [linters](https://github.com/mcandre/linters) provides an exhaustive collection of linters
* [ls](https://linux.die.net/man/1/ls) can describe many file and directory metadata entries
* [stank](https://github.com/mcandre/stank) analyzes executable and library shell scripts
