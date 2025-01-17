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
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
)

// tagListOutput is the output format of (skopeo list-tags), primarily so that we can format it with a simple json.MarshalIndent.
type tagListOutput struct {
	Repository string `json:",omitempty"`
	Tags       []string
}

type tagsOptions struct {
	global       *globalOptions
	image        *imageOptions
	retryOpts    *retry.Options
	registryType string // 新增参数
}

var transportHandlers = map[string]func(ctx context.Context, sys *types.SystemContext, opts *tagsOptions, userInput string) (repositoryName string, tagListing []string, err error){
	docker.Transport.Name():  listDockerRepoTags,
	archive.Transport.Name(): listDockerArchiveTags,
	"harbor":                 listHarborRepoTags, // 添加对 Harbor 的支持
}

// supportedTransports returns all the supported transports
func supportedTransports(joinStr string) string {
	res := maps.Keys(transportHandlers)
	sort.Strings(res)
	return strings.Join(res, joinStr)
}

func tagsCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := dockerImageFlags(global, sharedOpts, nil, "", "")
	retryFlags, retryOpts := retryFlags()

	opts := tagsOptions{
		global:       global,
		image:        imageOpts,
		retryOpts:    retryOpts,
		registryType: "registry", // 默认值为 registry
	}

	cmd := &cobra.Command{
		Use:   "list-tags [command options] SOURCE-IMAGE",
		Short: "List tags in the transport/repository specified by the SOURCE-IMAGE",
		Long: `Return the list of tags from the transport/repository "SOURCE-IMAGE"

Supported transports:
` + supportedTransports(" ") + `

See skopeo-list-tags(1) section "REPOSITORY NAMES" for the expected format
`,
		RunE:    commandAction(opts.run),
		Example: `skopeo list-tags docker://docker.io/fedora`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&retryFlags)
	flags.StringVar(&opts.registryType, "registry-type", "registry", "Specify the registry type (e.g., registry, harbor)")
	return cmd
}

// Customized version of the alltransports.ParseImageName and docker.ParseReference that does not place a default tag in the reference
// Would really love to not have this, but needed to enforce tag-less and digest-less names
func parseDockerRepositoryReference(refString string) (types.ImageReference, error) {
	dockerRefString, ok := strings.CutPrefix(refString, docker.Transport.Name()+"://")
	if !ok {
		return nil, fmt.Errorf("docker: image reference %s does not start with %s://", refString, docker.Transport.Name())
	}

	ref, err := reference.ParseNormalizedNamed(dockerRefString)
	if err != nil {
		return nil, err
	}

	if !reference.IsNameOnly(ref) {
		return nil, errors.New(`No tag or digest allowed in reference`)
	}

	// Checks ok, now return a reference. This is a hack because the tag listing code expects a full image reference even though the tag is ignored
	return docker.NewReference(reference.TagNameOnly(ref))
}

// List the tags from a repository contained in the imgRef reference. Any tag value in the reference is ignored
func listDockerTags(ctx context.Context, sys *types.SystemContext, imgRef types.ImageReference) (string, []string, error) {
	repositoryName := imgRef.DockerReference().Name()

	tags, err := docker.GetRepositoryTags(ctx, sys, imgRef)
	if err != nil {
		return ``, nil, fmt.Errorf("Error listing repository tags: %w", err)
	}
	return repositoryName, tags, nil
}

// return the tagLists from a docker repo
func listDockerRepoTags(ctx context.Context, sys *types.SystemContext, opts *tagsOptions, userInput string) (repositoryName string, tagListing []string, err error) {
	// Do transport-specific parsing and validation to get an image reference
	imgRef, err := parseDockerRepositoryReference(userInput)
	if err != nil {
		return
	}
	if err = retry.IfNecessary(ctx, func() error {
		repositoryName, tagListing, err = listDockerTags(ctx, sys, imgRef)
		return err
	}, opts.retryOpts); err != nil {
		return
	}
	return
}

// return the tagLists from a docker archive file
func listDockerArchiveTags(_ context.Context, sys *types.SystemContext, _ *tagsOptions, userInput string) (repositoryName string, tagListing []string, err error) {
	ref, err := alltransports.ParseImageName(userInput)
	if err != nil {
		return
	}

	tarReader, _, err := archive.NewReaderForReference(sys, ref)
	if err != nil {
		return
	}
	defer tarReader.Close()

	imageRefs, err := tarReader.List()
	if err != nil {
		return
	}

	var repoTags []string
	for imageIndex, items := range imageRefs {
		for _, ref := range items {
			repoTags, err = tarReader.ManifestTagsForReference(ref)
			if err != nil {
				return
			}
			// handle for each untagged image
			if len(repoTags) == 0 {
				repoTags = []string{fmt.Sprintf("@%d", imageIndex)}
			}
			tagListing = append(tagListing, repoTags...)
		}
	}

	return
}

// return the tagLists from a Harbor repo
func listHarborRepoTags(ctx context.Context, sys *types.SystemContext, opts *tagsOptions, userInput string) (repositoryName string, tagListing []string, err error) {
	// 解析 Harbor 仓库 URL
	domain, project, repo, err := parseHarborURL(userInput)
	if err != nil {
		return "", nil, err
	}

	// 获取认证信息
	username := opts.image.userName.Value()
	password := opts.image.password.Value()

	// 获取 Harbor 仓库的 tags
	tagListing, err = getHarborArtifactTags(ctx, domain, project, repo, username, password)
	if err != nil {
		return "", nil, err
	}

	repositoryName = fmt.Sprintf("%s/%s/%s", domain, project, repo)
	return
}

func (opts *tagsOptions) run(args []string, stdout io.Writer) (retErr error) {
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

	var repositoryName string
	var tagListing []string

	if opts.registryType == "harbor" {
		repositoryName, tagListing, err = listHarborRepoTags(ctx, sys, opts, args[0])
	} else {
		if val, ok := transportHandlers[transport.Name()]; ok {
			repositoryName, tagListing, err = val(ctx, sys, opts, args[0])
		} else {
			return fmt.Errorf("Unsupported transport '%s' for tag listing. Only supported: %s",
				transport.Name(), supportedTransports(", "))
		}
	}

	if err != nil {
		return err
	}

	outputData := tagListOutput{
		Repository: repositoryName,
		Tags:       tagListing,
	}

	out, err := json.MarshalIndent(outputData, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", string(out))

	return err
}

func getHarborArtifactTags(ctx context.Context, sourceHarborURL, projectName, repositoryName, username, password string) ([]string, error) {
	var allTags []string
	page := 1
	pageSize := 100 // 每页获取100个工件
	attemptedPages := 0

	for {
		attemptedPages++
		scheme := "https"

		artifactsURL := fmt.Sprintf("%s://%s/api/v2.0/projects/%s/repositories/%s/artifacts?page=%d&page_size=%d", scheme, sourceHarborURL, projectName, repositoryName, page, pageSize)

		req, err := http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
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
				body, _ := io.ReadAll(resp.Body)
				fmt.Printf("Unexpected status code with HTTPS on page %d: %d, body: %s\n", page, resp.StatusCode, string(body))
			}

			// HTTPS failed, use HTTP
			scheme = "http"
			artifactsURL = fmt.Sprintf("%s://%s/api/v2.0/projects/%s/repositories/%s/artifacts?page=%d&page_size=%d", scheme, sourceHarborURL, projectName, repositoryName, page, pageSize)

			req, err = http.NewRequestWithContext(ctx, "GET", artifactsURL, nil)
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

		// // 读取并打印原始响应体以进行调试
		// bodyBytes, err := io.ReadAll(resp.Body)
		// if err != nil {
		// 	return nil, fmt.Errorf("failed to read response body: %w", err)
		// }
		// fmt.Printf("Raw Response Body for Artifacts (Page %d, Scheme %s): %s\n", page, scheme, string(bodyBytes))

		// // 将读取到的响应体重置回响应体
		// resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// 解码响应体到工件切片
		var data []Artifact
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
		}

		if len(data) == 0 {
			fmt.Printf("No more artifacts found after attempting %d pages.\n", attemptedPages)
			break // 如果没有更多数据，退出循环
		}

		// 提取所有标签名称
		for _, artifact := range data {
			for _, tag := range artifact.Tags {
				allTags = append(allTags, tag.Name)
			}
		}

		page++

		if len(data) < pageSize {
			// fmt.Printf("Reached last page after %d pages.\n", attemptedPages)
			break // 如果返回的数据少于请求的数量，说明已经到达最后一页
		}
	}

	// If no tags were found, return an empty slice instead of an error
	if len(allTags) == 0 {
		fmt.Println("No tags found.")
		return allTags, nil
	}

	return allTags, nil
}

func parseHarborURL(rawURL string) (string, string, string, error) {
	// 移除 docker:// 前缀
	cleanURL := strings.TrimPrefix(rawURL, "docker://")

	// 分割 URL
	parts := strings.Split(cleanURL, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid Harbor URL: %s", rawURL)
	}

	domain := parts[0]
	project := parts[1]
	repo := parts[2]

	return domain, project, repo, nil
}
