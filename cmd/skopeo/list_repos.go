package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	flags.StringVar(&opts.registryType, "registry-type", "registry", "Specify the registry type (e.g., registry, harbor)")
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

	// 获取认证信息
	username := opts.image.userName.Value()
	password := opts.image.password.Value()

	// 获取 Harbor 仓库列表
	repoList, err := getHarborRepositories(ctx, domain, username, password)
	if err != nil {
		return nil, err
	}

	return repoList, nil
}

// getHarborRepositories 获取 Harbor 仓库列表
func getHarborRepositories(ctx context.Context, domain, username, password string) ([]string, error) {
	var allRepos []string

	// 获取所有项目
	projects, err := getHarborProjects(ctx, domain, username, password)
	if err != nil {
		return nil, err
	}

	// 获取每个项目下的仓库
	for _, project := range projects {
		repos, err := getProjectRepositories(ctx, domain, project.Name, username, password)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			allRepos = append(allRepos, fmt.Sprintf("%s/%s", project.Name, repo.Name))
		}
	}
	return allRepos, nil
}

// getHarborProjects retrieves all projects from the Harbor API, automatically handling both http and https.
type Project struct {
	ProjectID          int          `json:"project_id"`
	OwnerID            int          `json:"owner_id"`
	Name               string       `json:"name"`
	CreationTime       string       `json:"creation_time"`
	UpdateTime         string       `json:"update_time"`
	Deleted            bool         `json:"deleted"`
	OwnerName          string       `json:"owner_name"`
	CurrentUserID      int          `json:"current_user_role_id"`
	CurrentUserRoleIDs []int        `json:"current_user_role_ids"`
	RepoCount          int          `json:"repo_count"`
	ChartCount         int          `json:"chart_count"`
	Metadata           Metadata     `json:"metadata"`
	CVEWhitelist       CVEWhitelist `json:"cve_whitelist"`
}

// Metadata represents metadata associated with a project.
type Metadata struct {
	Public string `json:"public"`
}

// CVEWhitelist represents the CVE whitelist associated with a project.
type CVEWhitelist struct {
	ID           int      `json:"id"`
	ProjectID    int      `json:"project_id"`
	Items        []string `json:"items"`
	CreationTime string   `json:"creation_time"`
	UpdateTime   string   `json:"update_time"`
}

// getHarborProjects retrieves all projects from the Harbor API, automatically handling both http and https.
func getHarborProjects(ctx context.Context, domain, username, password string) ([]Project, error) {
	// Test HTTPS connection
	scheme := "https"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 注意：这会忽略TLS证书验证，仅用于测试环境
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(scheme + "://" + domain)
	if err != nil {
		// HTTPS failed, use HTTP
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: nil,
			},
		}
		scheme = "http"
	} else {
		defer resp.Body.Close()
		// HTTPS succeeded
	}

	baseURL := fmt.Sprintf("%s://%s/api/v2.0/projects?page=1&page_size=100", scheme, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 添加必要的头部信息
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// 设置基本认证
	if username != "" && password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	var projects []Project
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return projects, nil
}

type Repository struct {
	ArtifactCount int    `json:"artifact_count"`
	CreationTime  string `json:"creation_time"`
	ID            int    `json:"id"`
	Name          string `json:"name"`
	ProjectID     int    `json:"project_id"`
	PullCount     int    `json:"pull_count"`
	UpdateTime    string `json:"update_time"`
}

// getProjectRepositories retrieves all repositories for a specific project from the Harbor API, automatically handling both http and https.

func getProjectRepositories(ctx context.Context, sourceHarborURL, project, username, password string) ([]Repository, error) {
	var repositories []Repository
	page := 1
	pageSize := 100 // 每页获取100个仓库
	attemptedPages := 0

	for {
		attemptedPages++
		scheme := "https"

		reposURL := fmt.Sprintf("%s://%s/api/v2.0/projects/%s/repositories?page=%d&page_size=%d", scheme, sourceHarborURL, project, page, pageSize)

		req, err := http.NewRequestWithContext(ctx, "GET", reposURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// 构造 Basic Authentication header
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Authorization", "Basic "+auth)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 注意：这会忽略TLS证书验证，仅用于测试环境
			},
		}

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if err != nil {

				// fmt.Printf("HTTPS request failed on page %d: %v\n", page, err)
			} else {
				defer resp.Body.Close()
				// body, _ := io.ReadAll(resp.Body)
				// fmt.Printf("Unexpected status code with HTTPS on page %d: %d, body: %s\n", page, resp.StatusCode, string(body))
			}

			// HTTPS failed, use HTTP
			scheme = "http"
			reposURL = fmt.Sprintf("%s://%s/api/v2.0/projects/%s/repositories?page=%d&page_size=%d", scheme, sourceHarborURL, project, page, pageSize)

			req, err = http.NewRequestWithContext(ctx, "GET", reposURL, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create HTTP request: %w", err)
			}

			req.Header.Set("Authorization", "Basic "+auth)
			req.Header.Set("Accept", "application/json")

			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: nil,
				},
			}

			resp, err = client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("HTTP request failed on page %d: %w", page, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("unexpected status code with HTTP on page %d: %d, body: %s", page, resp.StatusCode, string(body))
			}
		} else {
			defer resp.Body.Close()
			// HTTPS succeeded
		}

		// 读取并打印原始响应体以进行调试
		// bodyBytes, err := io.ReadAll(resp.Body)
		// if err != nil {
		// 	return nil, fmt.Errorf("failed to read response body: %w", err)
		// }
		// fmt.Printf("Raw Response Body for Repositories (Page %d, Scheme %s): %s\n", page, scheme, string(bodyBytes))

		// // 将读取到的响应体重置回响应体
		// resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// 解码响应体到仓库切片
		var data []Repository
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
		}

		if len(data) == 0 {
			// fmt.Printf("No more repositories found after attempting %d pages.\n", attemptedPages)
			break // 如果没有更多数据，退出循环
		}

		repositories = append(repositories, data...)
		page++

		if len(data) < pageSize {
			// fmt.Printf("Reached last page after %d pages.\n", attemptedPages)
			break // 如果返回的数据少于请求的数量，说明已经到达最后一页
		}
	}

	// If no repositories were found, return an empty slice instead of an error
	if len(repositories) == 0 {
		// fmt.Println("No repositories found.")
		return repositories, nil
	}

	return repositories, nil
}

type Tag struct {
	Name string `json:"name"`
}

// Artifact represents the minimal structure needed to extract tags from an artifact.
type Artifact struct {
	Tags []Tag `json:"tags"`
}

// 获取 harbor repo的所有tag

func (opts *reposOptions) run(args []string, stdout io.Writer) (retErr error) {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 1 {
		return errorShouldDisplayUsage{errors.New("exactly one non-option argument expected")}
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
