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
`),
	Args: cobra.ExactArgs(2),
	// SilenceUsage: true,
	RunE: createKeyAndCert,
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

	rootCmd.AddCommand(createCmd)
}

func createKeyAndCert(cmd *cobra.Command, args []string) error {
	// these are guaranteed to exist by the ExactArgs(2) in the Command
	keyFile := args[0]
	certFile := args[1]

	signerKeyFile, err := cmd.Flags().GetString("signer-key")
	if err != nil {
		return err
	}
	signerCertFile, err := cmd.Flags().GetString("signer-cert")
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
	if signerKeyFile != "" || signerCertFile != "" {
		if signerKeyFile == "" || signerCertFile == "" {
			return errors.New("must specify both --signer-cert and --signer-key")
		}
		signer, err = certin.LoadKeyAndCert(signerKeyFile, signerCertFile)
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

	err = certin.Export(keyFile, certFile, cert)
	if err != nil {
		return err
	}

	if bundle != "" {
		err := fileConcat(bundle, keyFile, certFile, signerCertFile)
		if err != nil {
			return err
		}
		cmd.Printf("Success! Wrote: %s, %s, %s\n", keyFile, certFile, bundle)
		return nil
	}

	cmd.Printf("Success! Wrote: %s, %s\n", keyFile, certFile)
	return nil
}

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
