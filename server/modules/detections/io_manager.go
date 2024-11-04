// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/security-onion-solutions/securityonion-soc/config"
)

// go install go.uber.org/mock/mockgen@latest
//go:generate mockgen -destination mock/mock_iomanager.go -package mock . IOManager

type IOManager interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, contents []byte, perm fs.FileMode) error
	DeleteFile(path string) error
	ReadDir(path string) ([]os.DirEntry, error)
	RemoveAll(path string) error
	MakeRequest(*http.Request) (*http.Response, error)
	ExecCommand(cmd *exec.Cmd) ([]byte, int, time.Duration, error)
	WalkDir(root string, fn fs.WalkDirFunc) error
	CloneRepo(ctx context.Context, path string, repo string, branch *string) (err error)
	PullRepo(ctx context.Context, path string, branch *string) (pulled bool, reclone bool, failSync bool)
}

type ResourceManager struct {
	Config  *config.ServerConfig
	_client *http.Client
}

func (_ *ResourceManager) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (_ *ResourceManager) WriteFile(path string, contents []byte, perm fs.FileMode) error {
	return os.WriteFile(path, contents, perm)
}

func (_ *ResourceManager) DeleteFile(path string) error {
	return os.Remove(path)
}

func (_ *ResourceManager) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func (_ *ResourceManager) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (resman *ResourceManager) MakeRequest(req *http.Request) (*http.Response, error) {
	if resman._client == nil {
		// cache for reuse, the config values can't change without a server restart
		resman._client = resman.buildHttpClient()
	}

	return resman._client.Do(req)
}

func (resman *ResourceManager) buildHttpClient() *http.Client {
	transport := &http.Transport{}

	if resman.Config.Proxy != "" {
		p, err := url.Parse(resman.Config.Proxy)
		if err != nil {
			log.WithError(err).WithField("proxy", resman.Config.Proxy).Error("unable to parse proxy URL, not using proxy")
		} else {
			transport.Proxy = http.ProxyURL(p)
		}
	}

	if resman.Config.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if resman.Config.AdditionalCA != "" {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}

		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}

		pool.AppendCertsFromPEM([]byte(resman.Config.AdditionalCA))

		transport.TLSClientConfig.RootCAs = pool
	}

	return &http.Client{Transport: transport}
}

func (_ *ResourceManager) ExecCommand(cmd *exec.Cmd) (output []byte, exitCode int, runtime time.Duration, err error) {
	start := time.Now()
	output, err = cmd.CombinedOutput()
	runtime = time.Since(start)

	exitCode = cmd.ProcessState.ExitCode()

	return output, exitCode, runtime, err
}

func (_ *ResourceManager) WalkDir(root string, fn fs.WalkDirFunc) error {
	return filepath.WalkDir(root, fn)
}

func (rm *ResourceManager) CloneRepo(ctx context.Context, path string, repo string, branch *string) (err error) {
	proxyOpts, err := proxyToTransportOptions(rm.Config.Proxy)
	if err != nil {
		return err
	}

	opts := &git.CloneOptions{
		Depth:           1,
		SingleBranch:    true,
		URL:             repo,
		ProxyOptions:    proxyOpts,
		CABundle:        []byte(rm.Config.AdditionalCA),
		InsecureSkipTLS: rm.Config.InsecureSkipVerify,
	}

	if branch != nil && *branch != "" {
		opts.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", *branch))
	}

	_, err = git.PlainCloneContext(ctx, path, false, opts)

	return err
}

func (rm *ResourceManager) PullRepo(ctx context.Context, path string, branch *string) (pulled bool, reclone bool, failSync bool) {
	gitrepo, err := git.PlainOpen(path)
	if err != nil {
		log.WithError(err).WithField("repoPath", path).Error("failed to open repo, doing nothing with it")

		return false, true, false
	}

	work, err := gitrepo.Worktree()
	if err != nil {
		log.WithError(err).WithField("repoPath", path).Error("failed to get worktree, doing nothing with it")

		return false, true, false
	}

	err = work.Reset(&git.ResetOptions{
		Mode: git.HardReset,
	})
	if err != nil {
		log.WithError(err).WithField("repoPath", path).Error("failed to reset worktree, doing nothing with it")

		return false, true, false
	}

	proxyOpts, err := proxyToTransportOptions(rm.Config.Proxy)
	if err != nil {
		log.WithError(err).WithField("proxy", rm.Config.Proxy).Error("unable to parse proxy url, ignoring proxy")
	}

	opts := &git.PullOptions{
		Depth:           1,
		SingleBranch:    true,
		ProxyOptions:    proxyOpts,
		CABundle:        []byte(rm.Config.AdditionalCA),
		InsecureSkipTLS: rm.Config.InsecureSkipVerify,
	}

	if branch != nil && *branch != "" {
		opts.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", *branch))
	}

	err = work.PullContext(ctx, opts)
	if err != nil && err != git.NoErrAlreadyUpToDate {
		log.WithError(err).WithField("repoPath", path).Error("failed to pull repo, doing nothing with it")

		failSync = errors.Is(err, transport.ErrRepositoryNotFound)

		return false, !failSync, failSync
	}

	return err == nil, false, false
}
