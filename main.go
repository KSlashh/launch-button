package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

var function string
var keystorePath string
var args string
var typeArgs string
var network string
var functionId string
var packageDir string

var mainnet_url string = "https://fullnode.mainnet.aptoslabs.com"
var testnet_url string = "https://fullnode.testnet.aptoslabs.com/v1"

func init() {
	flag.StringVar(&keystorePath, "keystore", "", "keystore file path")
	flag.StringVar(&packageDir, "package-dir", "", "move package path")
	flag.StringVar(&args, "args", "", "Arguments combined with their type separated by spaces(wrapped by \").")
	flag.StringVar(&typeArgs, "type-args", "", "TypeTag arguments separated by spaces(wrapped by \").")
	flag.StringVar(&network, "network", "", "testnet | mainnet")
	flag.StringVar(&functionId, "function-id", "", "Function name as `<ADDRESS>::<MODULE_ID>::<FUNCTION_NAME>`")
	flag.StringVar(&function, "fun", "", "choose function to run:\n"+
		" run: lauch-button --fun run --function-id <FUNCTION_ID> --args <ARGS> --type-args <TYPE_ARGS> --network {testnet | mainnet} --keystore <KEYSTORE_FILE_PATH>\n "+
		" pubish: lauch-button --fun publish --package-dir <PACKAGE_DIR> --network {testnet | mainnet} --keystore <KEYSTORE_FILE_PATH>\n ")
	flag.Parse()
}

func main() {
	url := getNetworkUrl(network)
	priv := getPrivateKey(keystorePath)
	switch function {
	case "run":
		PrintResult(run(url, functionId, args, typeArgs, priv))
	case "publish":
		PrintResult(publish(url, packageDir, priv))
	default:
		fmt.Printf("Unknown function %s", function)
		flag.CommandLine.Usage()
		return
	}
}

func getPrivateKey(keystorePath string) string {
	fmt.Printf("Please type in password of %s: ", keystorePath)
	pass, err := terminal.ReadPassword(0)
	if err != nil {
		panic(fmt.Sprintf("fail to Parse private key, %v", err))
	}
	fmt.Println()
	password := string(pass)
	password = strings.Replace(password, "\n", "", -1)
	ks, err := ioutil.ReadFile(keystorePath)
	if err != nil {
		panic(fmt.Sprintf("fail to recover private key from keystore file, %v", err))
	}
	priv, err := keystore.DecryptKey(ks, password)
	if err != nil {
		panic(fmt.Sprintf("fail to recover private key from keystore file, %v", err))
	}
	return fmt.Sprintf("%x", crypto.FromECDSA(priv.PrivateKey))
}

func getNetworkUrl(network string) string {
	switch network {
	case "testnet":
		return testnet_url
	case "mainnet":
		return mainnet_url
	default:
		panic(fmt.Sprintf("unknown network: %s ,please choose from { `testnet` | `mainnet` }", network))
	}
}

func publish(url, packageDir, priv string) []string {
	cmd := exec.Command("aptos", "move", "publish",
		"--bytecode-version", "6",
		"--assume-yes",
		"--private-key", priv,
		"--url", url)
	if len(packageDir) != 0 {
		cmd.Args = append(cmd.Args, "--package-dir", packageDir)
	}
	res, err := RunCommand(cmd)
	if err != nil {
		panic(fmt.Sprintf("execute `aptos move publish` cmd error: %v", err))
	}
	return res
}

func run(url, functionId, functionArgs, typeArgs, priv string) []string {
	cmd := exec.Command("aptos", "move", "run",
		"--assume-yes",
		"--private-key", priv,
		"--url", url,
		"--function-id", functionId)
	if len(functionArgs) != 0 {
		functionArgs = strings.Replace(functionArgs, "\"", "", -1)
		functionArgs = strings.Replace(functionArgs, "'", "", -1)
		cmd.Args = append(cmd.Args, "--args")
		cmd.Args = append(cmd.Args, strings.Split(functionArgs, " ")...)
	}
	if len(typeArgs) != 0 {
		typeArgs = strings.Replace(typeArgs, "\"", "", -1)
		typeArgs = strings.Replace(typeArgs, "'", "", -1)
		cmd.Args = append(cmd.Args, "--type-args")
		cmd.Args = append(cmd.Args, strings.Split(typeArgs, " ")...)
	}
	res, err := RunCommand(cmd)
	if err != nil {
		panic(fmt.Sprintf("execute `aptos move run` cmd error: %v", err))
	}
	return res
}

func RunCommand(cmd *exec.Cmd) (result []string, err error) {
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	defer out.Close()
	cmd.Stderr = cmd.Stdout

	if err = cmd.Start(); err != nil {
		return
	}
	buff := make([]byte, 8)

	for {
		len, err := out.Read(buff)
		if err == io.EOF {
			break
		}
		result = append(result, string(buff[:len]))
	}
	cmd.Wait()
	return
}

func PrintResult(res []string) {
	str := ""
	for _, s := range res {
		str += s
	}
	fmt.Print(str)
}
