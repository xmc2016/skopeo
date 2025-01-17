package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type listAllOptions struct {
	global       *globalOptions
	image        *imageOptions
	retryOpts    *retry.Options
	output       string // 新增参数，用于指定输出文件
	registryType string // 新增参数，用于指定 registry 类型
}

type registryOutput struct {
	Images           map[string][]string `yaml:"images"`
	ImagesByTagRegex map[string]string   `yaml:"images-by-tag-regex"`
	ImagesBySemver   map[string]string   `yaml:"images-by-semver"`
	Credentials      credentials         `yaml:"credentials"`
	TLSVerify        bool                `yaml:"tls-verify"`
	CertDir          string              `yaml:"cert-dir"`
}

type credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func listAllCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := dockerImageFlags(global, sharedOpts, nil, "", "")
	retryFlags, retryOpts := retryFlags()

	opts := listAllOptions{
		global:       global,
		image:        imageOpts,
		retryOpts:    retryOpts,
		output:       "images.yaml", // 默认输出文件
		registryType: "registry",    // 默认值为 registry
	}

	cmd := &cobra.Command{
		Use:   "list-all [command options] SOURCE-IMAGE",
		Short: "List all repositories and their tags in the transport specified by the SOURCE-IMAGE",
		Long: `Return the list of all repositories and their tags from the transport "SOURCE-IMAGE"

Supported transports:
` + supportedRepoTransports(" ") + `

See skopeo-list-all(1) section "REPOSITORY NAMES" for the expected format
`,
		RunE:    commandAction(opts.run),
		Example: `skopeo list-all docker://docker.io`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&retryFlags)
	flags.StringVarP(&opts.output, "output", "o", "images.yaml", "Output file")
	flags.StringVar(&opts.registryType, "registry-type", "registry", "Specify the registry type (e.g., registry, harbor)")

	return cmd
}

func (opts *listAllOptions) run(args []string, stdout io.Writer) (retErr error) {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 1 {
		return errorShouldDisplayUsage{errors.New("exactly one non-option argument expected")}
	}

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}

	// 解析并验证 registry URL
	registryURL, err := parseRegistryURL(args[0])
	if err != nil {
		return err
	}

	transport := alltransports.TransportFromImageName("docker://" + registryURL)
	if transport == nil {
		return fmt.Errorf("Invalid transport format for '%s'", registryURL)
	}

	var repositoryNames []string

	if opts.registryType == "harbor" {
		repositoryNames, err = listHarborRepos(ctx, sys, &reposOptions{global: opts.global, image: opts.image, retryOpts: opts.retryOpts}, "docker://"+registryURL)
	} else {
		if val, ok := repoTransportHandlers[transport.Name()]; ok {
			repositoryNames, err = val(ctx, sys, &reposOptions{global: opts.global, image: opts.image, retryOpts: opts.retryOpts}, "docker://"+registryURL)
		} else {
			return fmt.Errorf("unsupported transport '%s' for repository listing. Only supported: %s",
				transport.Name(), supportedRepoTransports(", "))
		}
	}

	if err != nil {
		return err
	}

	registryData := map[string]registryOutput{
		registryURL: {
			Images:           make(map[string][]string),
			ImagesByTagRegex: make(map[string]string),
			ImagesBySemver:   make(map[string]string),
			Credentials: credentials{
				Username: opts.image.userName.Value(),
				Password: opts.image.password.Value(),
			},
			TLSVerify: !opts.image.tlsVerify.Present() || opts.image.tlsVerify.Value(),
			CertDir:   opts.global.registriesDirPath,
		},
	}

	for _, repo := range repositoryNames {
		var tags []string
		if opts.registryType == "harbor" {
			_, tags, err = listHarborRepoTags(ctx, sys, &tagsOptions{global: opts.global, image: opts.image, retryOpts: opts.retryOpts}, "docker://"+registryURL+"/"+repo)
		} else {
			tags, err = listTags(ctx, sys, "docker://"+registryURL+"/"+repo)
		}
		if err != nil {
			return err
		}
		fullRepoName := repo
		if tags != nil {
			registryData[registryURL].Images[fullRepoName] = tags
		} else {
			registryData[registryURL].Images[fullRepoName] = []string{}
		}
	}

	out, err := yaml.Marshal(&registryData)
	if err != nil {
		return err
	}

	file, err := os.Create(opts.output)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(out)
	if err != nil {
		return err
	}

	return err
}

func listTags(ctx context.Context, sys *types.SystemContext, image string) ([]string, error) {
	ref, err := alltransports.ParseImageName(image)
	if err != nil {
		return nil, err
	}

	tags, err := docker.GetRepositoryTags(ctx, sys, ref)
	if err != nil {
		return nil, err
	}

	sort.Strings(tags)
	return tags, nil
}
