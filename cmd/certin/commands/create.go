package commands

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/joemiller/certin"
	"github.com/spf13/cobra"
)

// createCmd represents the key and cert creation command
var createCmd = &cobra.Command{
	Use:   "create KEY CERT",
	Short: "Create new key pair and certificate.",
	Long:  "Create new key pair and certificate.",
	Example: indentor(`
# create self-signed cert
certin create example.key example.crt --cn="example.com"

# create root CA
certin create root.key root.crt --is-ca=true --cn="root CA"

# create intermediate CA, signed by root.key/crt
certin create intermediate.key intermediate.crt --signer-key root.key --signer-cert root.crt --is-ca=true --cn="intermediate CA"

# create leaf certificate with SubjectAltNames (SANs)
certin create example.key example.crt --signer-key intermediate.key --signer-cert intermediate.crt --cn="example.com" --sans="example.com,www.example.com"

# create a certificate signing request (CSR) instead of a signed certificate
certin create example.key example.csr --cn example.com
`),
	Args: cobra.ExactArgs(2),
	// SilenceUsage: true,
	RunE: create,
}

func init() {
	createCmd.Flags().StringP("signer-key", "k", "", "CA key to sign the CERT with. If omitted, a self-signed cert is generated.")
	createCmd.Flags().StringP("signer-cert", "c", "", "CA cert to sign the CERT with. If omitted, a self-signed cert is generated.")
	createCmd.Flags().String("cn", "", "Certificate common name")
	createCmd.Flags().StringSlice("o", []string{}, "Certificate organization")
	createCmd.Flags().StringSlice("ou", []string{}, "Certificate organizational unit")
	createCmd.Flags().StringP("duration", "d", "1y", "certificate duration. Examples of valid values: 1w, 1d, 2d3h5m, 1h30m, 10s")
	createCmd.Flags().Bool("is-ca", false, "create a CA cert capable of signing other certs")
	createCmd.Flags().StringP("key-type", "K", "rsa-2048", "key type to create (rsa-2048, rsa-3072, rsa-4096, ecdsa-256, ecdsa-384, ecdsa-512, ed25519)")
	createCmd.Flags().StringSlice("sans", []string{}, "Certificate SubjectAltNames, comma separated")
	createCmd.Flags().String("bundle", "", "(optional) Create combined bundle FILE containing private-key, certificate, and signing CA cert")
	createCmd.Flags().Bool("csr", false, "create a Certificate Signing Request (CSR) instead of a signed certificate")

	rootCmd.AddCommand(createCmd)
}

func create(cmd *cobra.Command, args []string) error {
	csr, err := cmd.Flags().GetBool("csr")
	if err != nil {
		return err
	}

	// if --csr=true, generate key + CSR
	if csr {
		return createKeyAndCSR(cmd, args)
	}

	// else, generate key + signed cert
	return createKeyAndCert(cmd, args)
}

func createKeyAndCert(cmd *cobra.Command, args []string) error {
	// these are guaranteed to exist by the ExactArgs(2) in the Command
	keyOut := args[0]
	certOut := args[1]

	signerKey, err := cmd.Flags().GetString("signer-key")
	if err != nil {
		return err
	}
	signerCert, err := cmd.Flags().GetString("signer-cert")
	if err != nil {
		return err
	}
	cn, err := cmd.Flags().GetString("cn")
	if err != nil {
		return err
	}
	o, err := cmd.Flags().GetStringSlice("o")
	if err != nil {
		return err
	}
	ou, err := cmd.Flags().GetStringSlice("ou")
	if err != nil {
		return err
	}
	durationStr, err := cmd.Flags().GetString("duration")
	if err != nil {
		return err
	}
	isCA, err := cmd.Flags().GetBool("is-ca")
	if err != nil {
		return err
	}
	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		return err
	}
	sans, err := cmd.Flags().GetStringSlice("sans")
	if err != nil {
		return err
	}
	bundle, err := cmd.Flags().GetString("bundle")
	if err != nil {
		return err
	}

	var signer *certin.KeyAndCert
	if signerKey != "" || signerCert != "" {
		if signerKey == "" || signerCert == "" {
			return errors.New("must specify both --signer-cert and --signer-key")
		}
		signer, err = certin.LoadKeyAndCert(signerKey, signerCert)
		if err != nil {
			return err
		}
	}

	duration, err := ParseDuration(durationStr)
	if err != nil {
		return err
	}

	req := certin.Request{
		CN:       cn,
		O:        o,
		OU:       ou,
		SANs:     sans,
		Duration: duration,
		IsCA:     isCA,
		KeyType:  keyType,
	}

	cert, err := certin.NewCert(signer, req)
	if err != nil {
		return err
	}

	err = certin.ExportKeyAndCert(keyOut, certOut, cert)
	if err != nil {
		return err
	}

	if bundle != "" {
		err := fileConcat(bundle, keyOut, certOut, signerCert)
		if err != nil {
			return err
		}
		cmd.Printf("Success! Wrote: %s, %s, %s\n", keyOut, certOut, bundle)
		return nil
	}

	cmd.Printf("Success! Wrote: %s, %s\n", keyOut, certOut)
	return nil
}

func createKeyAndCSR(cmd *cobra.Command, args []string) error {
	// these are guaranteed to exist by the ExactArgs(2) in the Command
	keyOut := args[0]
	csrOut := args[1]

	cn, err := cmd.Flags().GetString("cn")
	if err != nil {
		return err
	}
	o, err := cmd.Flags().GetStringSlice("o")
	if err != nil {
		return err
	}
	ou, err := cmd.Flags().GetStringSlice("ou")
	if err != nil {
		return err
	}
	durationStr, err := cmd.Flags().GetString("duration")
	if err != nil {
		return err
	}
	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		return err
	}
	sans, err := cmd.Flags().GetStringSlice("sans")
	if err != nil {
		return err
	}
	bundle, err := cmd.Flags().GetString("bundle")
	if err != nil {
		return err
	}

	duration, err := ParseDuration(durationStr)
	if err != nil {
		return err
	}

	req := certin.Request{
		CN:       cn,
		O:        o,
		OU:       ou,
		SANs:     sans,
		Duration: duration,
		KeyType:  keyType,
	}

	csr, err := certin.NewCSR(req)
	if err != nil {
		return err
	}

	err = certin.ExportKeyAndCSR(keyOut, csrOut, csr)
	if err != nil {
		return err
	}

	if bundle != "" {
		err := fileConcat(bundle, keyOut, csrOut)
		if err != nil {
			return err
		}
		cmd.Printf("Success! Wrote: %s, %s, %s\n", keyOut, csrOut, bundle)
		return nil
	}

	cmd.Printf("Success! Wrote: %s, %s\n", keyOut, csrOut)
	return nil
}

// fileConcat creates a single file 'out' containing the contents of one or more files concatenated.
func fileConcat(out string, in ...string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}

	for _, i := range in {
		b, err := ioutil.ReadFile(i)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		if err != nil {
			return err
		}
	}
	return nil
}
