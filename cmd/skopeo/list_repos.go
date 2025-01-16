package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/archive"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
)

// repoListOutput is the output format of (skopeo list-repos), primarily so that we can format it with a simple json.MarshalIndent.
type repoListOutput struct {
	Repositories []string
}

type reposOptions struct {
	global       *globalOptions
	image        *imageOptions
	retryOpts    *retry.Options
	registryType string // 新增参数
}

var repoTransportHandlers = map[string]func(ctx context.Context, sys *types.SystemContext, opts *reposOptions, userInput string) (repositoryNames []string, err error){
	docker.Transport.Name():  listDockerRepos,
	archive.Transport.Name(): listDockerArchiveRepos,
	"harbor":                 listHarborRepos, // 添加对 Harbor 的支持
}

// supportedTransports returns all the supported transports
func supportedRepoTransports(joinStr string) string {
	res := maps.Keys(repoTransportHandlers)
	sort.Strings(res)
	return strings.Join(res, joinStr)
}

func reposCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := dockerImageFlags(global, sharedOpts, nil, "", "")
	retryFlags, retryOpts := retryFlags()

	opts := reposOptions{
		global:       global,
		image:        imageOpts,
		retryOpts:    retryOpts,
		registryType: "registry", // 默认值为 registry
	}

	cmd := &cobra.Command{
		Use:   "list-repos [command options] SOURCE-IMAGE",
		Short: "List repositories in the transport specified by the SOURCE-IMAGE",
		Long: `Return the list of repositories from the transport "SOURCE-IMAGE"

Supported transports:
` + supportedRepoTransports(" ") + `

See skopeo-list-repos(1) section "REPOSITORY NAMES" for the expected format
`,
		RunE:    commandAction(opts.run),
		Example: `skopeo list-repos docker://docker.io`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&retryFlags)
	return cmd
}

// List the repositories from a docker registry
func listDockerRepos(ctx context.Context, sys *types.SystemContext, opts *reposOptions, userInput string) ([]string, error) {
	// 解析 Docker 仓库 URL
	domain, err := parseRegistryURL(userInput)
	if err != nil {
		return nil, err
	}

	// 获取认证信息
	username := opts.image.userName.Value()
	password := opts.image.password.Value()
	// 获取仓库列表
	repoList, err := getDockerRepositories(ctx, domain, username, password, "https")
	if err != nil {
		return nil, err
	}

	return repoList, nil
}

// getDockerRepositories 获取 Docker 仓库列表
func getDockerRepositories(ctx context.Context, domain, username, password string, scheme string) ([]string, error) {
	// Setup authentication
	auth := authn.Anonymous
	if username != "" && password != "" {
		auth = authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		})
	}

	// Configure registry options
	opts := []name.Option{}
	if scheme == "http" {
		opts = append(opts, name.Insecure)
	}
	//fmt.Print(domain)
	// Create registry reference
	reg, err := name.NewRegistry(domain, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registry URL: %v", err)
	}

	// Get repository list with remote options
	remoteOpts := []remote.Option{remote.WithAuth(auth)}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{Transport: tr}
	if _, err = client.Get(scheme + "://" + domain); err != nil {
		// HTTPS failed, use HTTP
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: nil,
			},
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(client.Transport))
		scheme = "http"
	} else {
		// HTTPS succeeded
		remoteOpts = append(remoteOpts, remote.WithTransport(tr))
		scheme = "https"
	}

	repos, err := remote.Catalog(ctx, reg, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %v", err)
	}

	return repos, nil
}

// List the repositories from a docker archive file
func listDockerArchiveRepos(_ context.Context, sys *types.SystemContext, opts *reposOptions, userInput string) ([]string, error) {
	// Implement the logic to list repositories from a docker archive file
	// This is a placeholder implementation
	return []string{"archiveRepo1", "archiveRepo2"}, nil
}

// List the repositories from a Harbor registry
func listHarborRepos(ctx context.Context, sys *types.SystemContext, opts *reposOptions, userInput string) ([]string, error) {
	// 解析 Harbor 仓库 URL
	domain, err := parseRegistryURL(userInput)
	if err != nil {
		return nil, err
	}

	// 获取 Harbor 仓库列表
	url := fmt.Sprintf("%s/api/v2.0/projects", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list repositories: %s", resp.Status)
	}

	var projects []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, err
	}

	var repoList []string
	for _, project := range projects {
		repoList = append(repoList, project.Name)
	}

	return repoList, nil
}

func (opts *reposOptions) run(args []string, stdout io.Writer) (retErr error) {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 1 {
		return errorShouldDisplayUsage{errors.New("Exactly one non-option argument expected")}
	}

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}

	transport := alltransports.TransportFromImageName(args[0])
	if transport == nil {
		// 解析并验证 registry URL
		registryURL, err := parseRegistryURL(args[0])
		if err != nil {
			return err
		}
		args[0] = "docker://" + registryURL
		transport = alltransports.TransportFromImageName(args[0])
	}

	var repositoryNames []string

	if opts.registryType == "harbor" {
		repositoryNames, err = listHarborRepos(ctx, sys, opts, args[0])
	} else {
		if val, ok := repoTransportHandlers[transport.Name()]; ok {
			repositoryNames, err = val(ctx, sys, opts, args[0])
		} else {
			return fmt.Errorf("Unsupported transport '%s' for repository listing. Only supported: %s",
				transport.Name(), supportedRepoTransports(", "))
		}
	}

	if err != nil {
		return err
	}

	outputData := repoListOutput{
		Repositories: repositoryNames,
	}

	out, err := json.MarshalIndent(outputData, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", string(out))

	return err
}

func parseRegistryURL(rawURL string) (string, error) {
	// 移除 docker:// 前缀
	cleanURL := strings.TrimPrefix(rawURL, "docker://")

	// 如果包含协议，移除协议
	if strings.Contains(cleanURL, "://") {
		parts := strings.Split(cleanURL, "://")
		if len(parts) == 2 {
			cleanURL = parts[1]
		}
	}

	// 验证是否为有效的主机名
	if strings.Contains(cleanURL, "/") {
		// 允许包含路径的 URL
		return cleanURL, nil
	}

	// 返回清理后的 URL
	return cleanURL, nil
}
