package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/containers/image/v5/pkg/cli"
	"github.com/containers/image/v5/signature"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

type standaloneSignOptions struct {
	output         string // Output file path
	passphraseFile string // Path pointing to a passphrase file when signing
}

func standaloneSignCmd() *cobra.Command {
	opts := standaloneSignOptions{}
	cmd := &cobra.Command{
		Use:   "standalone-sign [command options] MANIFEST DOCKER-REFERENCE KEY-FINGERPRINT --output|-o SIGNATURE",
		Short: "Create a signature using local files",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.StringVarP(&opts.output, "output", "o", "", "output the signature to `SIGNATURE`")
	flags.StringVarP(&opts.passphraseFile, "passphrase-file", "", "", "file that contains a passphrase for the --sign-by key")
	return cmd
}

func (opts *standaloneSignOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 3 || opts.output == "" {
		return errors.New("Usage: skopeo standalone-sign manifest docker-reference key-fingerprint -o signature")
	}
	manifestPath := args[0]
	dockerReference := args[1]
	fingerprint := args[2]

	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading %s: %w", manifestPath, err)
	}

	mech, err := signature.NewGPGSigningMechanism()
	if err != nil {
		return fmt.Errorf("Error initializing GPG: %w", err)
	}
	defer mech.Close()

	passphrase, err := cli.ReadPassphraseFile(opts.passphraseFile)
	if err != nil {
		return err
	}

	signature, err := signature.SignDockerManifestWithOptions(manifest, dockerReference, mech, fingerprint, &signature.SignOptions{Passphrase: passphrase})
	if err != nil {
		return fmt.Errorf("Error creating signature: %w", err)
	}

	if err := os.WriteFile(opts.output, signature, 0644); err != nil {
		return fmt.Errorf("Error writing signature to %s: %w", opts.output, err)
	}
	return nil
}

type standaloneVerifyOptions struct {
	publicKeyFile string
}

func standaloneVerifyCmd() *cobra.Command {
	opts := standaloneVerifyOptions{}
	cmd := &cobra.Command{
		Use:   "standalone-verify MANIFEST DOCKER-REFERENCE KEY-FINGERPRINT SIGNATURE",
		Short: "Verify a signature using local files",
		Long: `Verify a signature using local files

KEY-FINGERPRINT can be an exact fingerprint, or "any" if you trust all the keys in the public key file.`,
		RunE: commandAction(opts.run),
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.publicKeyFile, "public-key-file", "", `File containing public keys. If not specified, will use local GPG keys.`)
	adjustUsage(cmd)
	return cmd
}

func (opts *standaloneVerifyOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 4 {
		return errors.New("Usage: skopeo standalone-verify manifest docker-reference key-fingerprint signature")
	}
	manifestPath := args[0]
	expectedDockerReference := args[1]
	expectedFingerprint := args[2]
	signaturePath := args[3]

	if opts.publicKeyFile == "" && expectedFingerprint == "any" {
		return fmt.Errorf("Cannot use any fingerprint without a public key file")
	}
	unverifiedManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading manifest from %s: %w", manifestPath, err)
	}
	unverifiedSignature, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("Error reading signature from %s: %w", signaturePath, err)
	}

	var mech signature.SigningMechanism
	var fingerprints []string
	if opts.publicKeyFile != "" {
		publicKeys, err := os.ReadFile(opts.publicKeyFile)
		if err != nil {
			return fmt.Errorf("Error reading public keys from %s: %w", opts.publicKeyFile, err)
		}
		mech, fingerprints, err = signature.NewEphemeralGPGSigningMechanism(publicKeys)
	} else {
		mech, err = signature.NewGPGSigningMechanism()
	}
	if err != nil {
		return fmt.Errorf("Error initializing GPG: %w", err)
	}
	defer mech.Close()

	if opts.publicKeyFile != "" && expectedFingerprint == "any" {
		_, expectedFingerprint, err = mech.Verify(unverifiedSignature)
		if err != nil {
			return fmt.Errorf("Could not determine fingerprint from signature: %w", err)
		}
		if !slices.Contains(fingerprints, expectedFingerprint) {
			// This is theoretically impossible because mech.Verify only works if it can identify the key based on the signature
			return fmt.Errorf("Signature fingerprint not found in public key file: %s", expectedFingerprint)
		}
	}

	sig, err := signature.VerifyDockerManifestSignature(unverifiedSignature, unverifiedManifest, expectedDockerReference, mech, expectedFingerprint)
	if err != nil {
		return fmt.Errorf("Error verifying signature: %w", err)
	}

	fmt.Fprintf(stdout, "Signature verified using fingerprint %s, digest %s\n", expectedFingerprint, sig.DockerManifestDigest)
	return nil
}

// WARNING: Do not use the contents of this for ANY security decisions,
// and be VERY CAREFUL about showing this information to humans in any way which suggest that these values “are probably” reliable.
// There is NO REASON to expect the values to be correct, or not intentionally misleading
// (including things like “✅ Verified by $authority”)
//
// The subcommand is undocumented, and it may be renamed or entirely disappear in the future.
type untrustedSignatureDumpOptions struct {
}

func untrustedSignatureDumpCmd() *cobra.Command {
	opts := untrustedSignatureDumpOptions{}
	cmd := &cobra.Command{
		Use:    "untrusted-signature-dump-without-verification SIGNATURE",
		Short:  "Dump contents of a signature WITHOUT VERIFYING IT",
		RunE:   commandAction(opts.run),
		Hidden: true,
	}
	adjustUsage(cmd)
	return cmd
}

func (opts *untrustedSignatureDumpOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("Usage: skopeo untrusted-signature-dump-without-verification signature")
	}
	untrustedSignaturePath := args[0]

	untrustedSignature, err := os.ReadFile(untrustedSignaturePath)
	if err != nil {
		return fmt.Errorf("Error reading untrusted signature from %s: %w", untrustedSignaturePath, err)
	}

	untrustedInfo, err := signature.GetUntrustedSignatureInformationWithoutVerifying(untrustedSignature)
	if err != nil {
		return fmt.Errorf("Error decoding untrusted signature: %v", err)
	}
	untrustedOut, err := json.MarshalIndent(untrustedInfo, "", "    ")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(untrustedOut))
	return nil
}
