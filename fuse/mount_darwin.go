// Copyright 2016 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func getMaxWrite() int {
	return 1 << 20
}

func unixgramSocketpair() (l, r *os.File, err error) {
	fd, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, os.NewSyscallError("socketpair",
			err.(syscall.Errno))
	}
	l = os.NewFile(uintptr(fd[0]), "socketpair-half1")
	r = os.NewFile(uintptr(fd[1]), "socketpair-half2")
	return
}

// Create a FUSE FS on the specified mount point.  The returned
// mount point is always absolute.
func mount(mountPoint string, opts *MountOptions, ready chan<- error) (fd int, err error) {
	// Prefer FUSE-T (kext-less, NFS-backed) when available.
	if bin, fusetErr := fusetBinary(); fusetErr == nil {
		return mountFuset(bin, mountPoint, opts, ready)
	}

	return mountMacfuse(mountPoint, opts, ready)
}

// mountMacfuse mounts via the traditional macFUSE mount helper
// (mount_macfuse or mount_osxfuse).
func mountMacfuse(mountPoint string, opts *MountOptions, ready chan<- error) (fd int, err error) {
	local, remote, err := unixgramSocketpair()
	if err != nil {
		return
	}

	defer local.Close()
	defer remote.Close()

	bin, err := macfuseBinary()
	if err != nil {
		return 0, err
	}

	cmd := exec.Command(bin,
		"-o", strings.Join(opts.optionsStrings(), ","),
		"-o", fmt.Sprintf("iosize=%d", opts.MaxWrite),
		mountPoint)
	cmd.ExtraFiles = []*os.File{remote} // fd would be (index + 3)
	cmd.Env = append(os.Environ(),
		"_FUSE_CALL_BY_LIB=",
		"_FUSE_DAEMON_PATH="+os.Args[0],
		"_FUSE_COMMFD=3",
		"_FUSE_COMMVERS=2",
		"MOUNT_OSXFUSE_CALL_BY_LIB=",
		"MOUNT_OSXFUSE_DAEMON_PATH="+os.Args[0])

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	if err = cmd.Start(); err != nil {
		return
	}

	fd, err = getConnection(local)
	if err != nil {
		return -1, err
	}

	go func() {
		// On macos, mount_osxfuse is not just a suid
		// wrapper. It interacts with the FS setup, and will
		// not exit until the filesystem has successfully
		// responded to INIT and STATFS. This means we can
		// only wait on the mount_osxfuse process after the
		// server has fully started
		if err := cmd.Wait(); err != nil {
			err = fmt.Errorf("mount_osxfusefs failed: %v. Stderr: %s, Stdout: %s",
				err, errOut.String(), out.String())
		}

		ready <- err
		close(ready)
	}()

	// golang sets CLOEXEC on file descriptors when they are
	// acquired through normal operations (e.g. open).
	// Buf for fd, we have to set CLOEXEC manually
	syscall.CloseOnExec(fd)

	return fd, err
}

// mountFuset mounts via FUSE-T's go-nfsv4 server, which translates
// the FUSE protocol to NFSv4 entirely in userspace (no kernel
// extension required). Communication uses two Unix socket pairs:
//
//   - A data socket (child fd 3) for the FUSE protocol
//   - A monitoring socket (child fd 4) for mount lifecycle coordination
//
// Unlike macFUSE, FUSE-T does not pass a /dev/fuse file descriptor
// via SCM_RIGHTS. Instead, the FUSE protocol flows directly over the
// data socket. The parent sends "mount" on the monitoring socket and
// waits for a 4-byte acknowledgement confirming the NFS mount
// succeeded.
func mountFuset(bin string, mountPoint string, opts *MountOptions, ready chan<- error) (fd int, err error) {
	// Data socket pair — the FUSE protocol flows directly over this
	// socket (no /dev/fuse fd passing).
	local, remote, err := unixgramSocketpair()
	if err != nil {
		return 0, err
	}
	defer remote.Close()

	// Monitoring socket pair — mount lifecycle coordination.
	localMon, remoteMon, err := unixgramSocketpair()
	if err != nil {
		local.Close()
		return 0, err
	}
	defer remoteMon.Close()

	// Build go-nfsv4 arguments.
	var args []string

	volName := opts.FsName
	if volName == "" {
		volName = opts.Name
	}
	if volName != "" {
		args = append(args, "-n", volName)
	}

	// Use a short NFS attribute cache timeout. The default (unlimited)
	// can cause NFS client deadlocks under heavy concurrent access.
	// 2 seconds provides adequate caching for directory traversals
	// while avoiding stale-handle issues.
	args = append(args, "--attrcache-timeout=2")

	args = append(args, mountPoint)

	cmd := exec.Command(bin, args...)
	cmd.ExtraFiles = []*os.File{remote, remoteMon} // fd 3 = data, fd 4 = monitor
	cmd.Env = append(os.Environ(),
		"_FUSE_COMMFD=3",
		"_FUSE_MONFD=4",
		"_FUSE_COMMVERS=2",
		"_FUSE_CALL_BY_LIB=",
		"_FUSE_DAEMON_PATH="+os.Args[0])

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	if err = cmd.Start(); err != nil {
		local.Close()
		localMon.Close()
		return 0, fmt.Errorf("fuse-t: start %s: %w", bin, err)
	}

	// FUSE-T sends the FUSE protocol directly over the data socket
	// rather than passing a /dev/fuse fd via SCM_RIGHTS. Duplicate
	// the socket fd so the Go runtime's finaliser on local doesn't
	// close the connection out from under the server.
	fd, err = syscall.Dup(int(local.Fd()))
	if err != nil {
		local.Close()
		localMon.Close()
		cmd.Process.Kill()
		return -1, fmt.Errorf("fuse-t: dup: %w", err)
	}
	local.Close()
	syscall.CloseOnExec(fd)

	go func() {
		defer localMon.Close()

		// Signal go-nfsv4 to perform the NFS mount.
		if _, werr := localMon.Write([]byte("mount")); werr != nil {
			ready <- fmt.Errorf("fuse-t: monitor write: %w", werr)
			close(ready)
			return
		}

		// Wait for 4-byte acknowledgement.
		ack := make([]byte, 4)
		if _, rerr := localMon.Read(ack); rerr != nil {
			ready <- fmt.Errorf("fuse-t: mount acknowledgement: %w", rerr)
			close(ready)
			return
		}

		// go-nfsv4 stays running as the NFS server for the
		// lifetime of the mount.  We do not Wait() here —
		// the process exits when the filesystem is unmounted.
		ready <- nil
		close(ready)
	}()

	return fd, nil
}

func unmount(dir string, opts *MountOptions) error {
	return syscall.Unmount(dir, 0)
}

// fusetBinary locates the FUSE-T go-nfsv4 server binary.
// The FUSE_NFSSRV_PATH environment variable overrides the default
// search paths.
func fusetBinary() (string, error) {
	if p := os.Getenv("FUSE_NFSSRV_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	paths := []string{
		"/usr/local/bin/go-nfsv4",
		"/Library/Application Support/fuse-t/bin/go-nfsv4",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("fuse-t: go-nfsv4 not found")
}

// macfuseBinary locates the macFUSE mount helper binary.
func macfuseBinary() (string, error) {
	paths := []string{
		"/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse",
		"/Library/Filesystems/osxfuse.fs/Contents/Resources/mount_osxfuse",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("no FUSE mount utility found")
}
