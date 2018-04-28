package main

import (
	"github.com/codegangsta/martini"
	"github.com/martini-contrib/render"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"crypto/rsa"
	"encoding/pem"
	"crypto/x509"
	"crypto/rand"

	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"encoding/base64"
	"fmt"
	"regexp"
	"path"
	"strings"
	"path/filepath"
)

func main() {
	m := martini.Classic()

	m.Use(render.Renderer(render.Options{
		Directory:  "templates",
		Extensions: []string{".html"},
	}))

	m.Get("/", func(render render.Render, log *log.Logger) {
		render.Redirect("/git")
		//render.HTML(200, "index", nil)
	})

	/*m.Post("/upload", func(r *http.Request) (int, string) {
		log.Println("parsing form")
		err := r.ParseMultipartForm(100000)
		if err != nil {
			return http.StatusInternalServerError, err.Error()
		}

		files := r.MultipartForm.File["files"]
		for i, _ := range files {
			log.Println("getting handle to file")
			file, err := files[i].Open()
			defer file.Close()
			if err != nil {
				return http.StatusInternalServerError, err.Error()
			}

			log.Println("creating destination file")
			dst, err := os.Create("./uploads/" + files[i].Filename)
			defer dst.Close()
			if err != nil {
				return http.StatusInternalServerError, err.Error()
			}

			log.Println("copying the uploaded file to the destination file")
			if _, err := io.Copy(dst, file); err != nil {
				return http.StatusInternalServerError, err.Error()
			}
		}

		return 200, "ok"
	})

	m.Get("/unzip", func(render render.Render, log *log.Logger) (int, string) {
		os.RemoveAll("./tmp/")
		os.MkdirAll("./tmp/", 0755)

		cmd := exec.Command("unzip", "../uploads/note.zip")
		cmd.Dir = "./tmp/"
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("cmd.Run() failed with %s\n", err)
			return 500, "error: " + err.Error()
		}
		log.Printf("combined out:\n%s\n", string(out))

		return 200, "unzipped"
	})

	m.Get("/file", func(writer http.ResponseWriter, request *http.Request) {
		//First of check if Get is set in the URL
		Filename := "./tmp/note/note.pdf"
		//Check if file exists and open
		Openfile, err := os.Open(Filename)
		defer Openfile.Close() //Close after function return
		if err != nil {
			//File not found, send 404
			http.Error(writer, "File not found.", 404)
			return
		}

		//File is found, create and send the correct headers

		//Get the Content-Type of the file
		//Create a buffer to store the header of the file in
		FileHeader := make([]byte, 512)
		//Copy the headers into the FileHeader buffer
		Openfile.Read(FileHeader)
		//Get content type of file
		FileContentType := http.DetectContentType(FileHeader)

		//Get the file size
		FileStat, _ := Openfile.Stat()                     //Get info from file
		FileSize := strconv.FormatInt(FileStat.Size(), 10) //Get file size as a string

		//Send the headers
		writer.Header().Set("Content-Disposition", "attachment; filename="+Filename)
		writer.Header().Set("Content-Type", FileContentType)
		writer.Header().Set("Content-Length", FileSize)

		//Send the file
		//We read 512 bytes from the file already so we reset the offset back to 0
		Openfile.Seek(0, 0)
		io.Copy(writer, Openfile) //'Copy' the file to the client
		return
	})*/

	m.Get("/git", func(render render.Render, log *log.Logger) {
		token, err := GenerateRandomString(6)
		if err != nil {
			// Serve an appropriately vague error to the
			// user, but log the details internally.
		}
		generateRSA(token)
		render.Redirect("/git/" + token)
	})

	m.Get("/git/:id", func(params martini.Params, render render.Render, log *log.Logger) {
		token := params["id"]

		exist, pubkeyPath := checkToken(token)
		if !exist {
			render.Text(404, "Bad id")
			return
		}
		dat, err := ioutil.ReadFile(pubkeyPath)
		if err != nil {
			render.Text(404, "Bad id")
			return
		}
		key := string(dat)

		cloneUrl := "http://latex.mbv.space/git/" + token + "/clone"

		render.HTML(200, "git", map[string]interface{}{"Token": token, "Key": key, "CloneUrl": cloneUrl})
	})

	m.Post("/git/:id/clone", func(params martini.Params, render render.Render, request *http.Request, log *log.Logger) {
		token := params["id"]
		exist, _ := checkToken(token)
		if !exist {
			render.Text(404, "Bad id")
			return
		}

		request.ParseForm()
		gitUrl := request.Form.Get("git-url")

		var re = regexp.MustCompile(`^(?:git|ssh|https?|git@[-\w.]+):(//)?([\w./\-@]*?)(\.git)$`)

		log.Println(gitUrl)

		if !re.MatchString(gitUrl) {
			render.Text(400, "Invalid git url")
			return
		}

		pathNote := request.Form.Get("path-note")

		var rePath = regexp.MustCompile(`^[\w-]+(\/[\w-]+)*$`)

		if !rePath.MatchString(pathNote) {
			render.Text(400, "Invalid path to tex file: "+pathNote+".tex")
			return
		}

		var dir, _ = os.Getwd()

		privatekeyPath := dir + "/keys/" + token + "/id_rsa"

		sessionToken, err := GenerateRandomString(6)
		if err != nil {
			// Serve an appropriately vague error to the
			// user, but log the details internally.
		}

		tmpDirPath := dir + "/tmp/" + token + "/" + sessionToken

		os.RemoveAll(tmpDirPath)
		os.MkdirAll(tmpDirPath, 0755)

		cmdGit := "git clone --depth 1 '" + gitUrl + "' note"

		cmd := exec.Command("/bin/sh", "-c", cmdGit)

		env := os.Environ()
		gitSshCommand := "ssh -i " + privatekeyPath
		env = append(env, fmt.Sprintf("GIT_SSH_COMMAND=%s", gitSshCommand))
		cmd.Env = env

		cmd.Dir = tmpDirPath

		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("cmd.Run() failed with %s\n", err)
			log.Printf("combined out:\n%s\n", string(out))
			render.Text(500, "error git: "+err.Error()+"\n message: "+string(out))
			return
		}
		log.Printf("combined out:\n%s\n", string(out))

		latexPath := tmpDirPath + "/note/" + pathNote + ".tex"

		fileInfo, err := os.Stat(latexPath)
		if os.IsNotExist(err) {
			render.Text(400, "File doesn't exist: "+pathNote+".tex")
			return
		}

		latexName := fileInfo.Name()
		latexDir := path.Dir(latexPath)

		latexResultPath := latexDir + "/" + strings.TrimSuffix(latexName, filepath.Ext(latexName)) + ".pdf"

		tryChangePreambleFont(latexDir)

		// remove pdf

		log.Println(latexDir)
		log.Println(latexResultPath)

		os.Remove(latexResultPath)

		//render.Text(200, "cloned")

		latexCmd := "docker run -v " + latexDir + "/:/root/note/ terehovk/diploma-latex:0.1 /root/run.sh " + latexName

		cmdNote := exec.Command("/bin/sh", "-c", latexCmd)

		outNote, err := cmdNote.CombinedOutput()
		if err != nil {
			log.Printf("cmd.Run() failed with %s\n", err)
			render.Text(500, "error: "+err.Error())
		}

		resultFilePath := tmpDirPath + "/note.pdf"

		os.Remove(resultFilePath)

		cpCmd := exec.Command("cp", latexResultPath, resultFilePath)
		err = cpCmd.Run()
		if err != nil {
			log.Printf("Not found pdf %s\n", err)
			render.Text(500, "error Not found pdf: "+err.Error())
		}
		//log.Printf("combined out:\n%s\n", string(out))

		url := "http://latex.mbv.space/git/" + token + "/download/" + sessionToken
		//render.Text(200, url+"\nlatex:"+string(outNote))

		render.HTML(200, "latex", map[string]interface{}{"Token": token, "SessionToken": sessionToken, "Log": string(outNote), "Url": url})
	})

	m.Get("/git/:id/download/:session", func(params martini.Params, render render.Render, writer http.ResponseWriter, request *http.Request, log *log.Logger) {

		token := params["id"]
		exist, _ := checkToken(token)
		if !exist {
			render.Text(404, "Bad id")
			return
		}

		sessionToken := params["session"]

		var dir, _ = os.Getwd()

		filePath := dir + "/tmp/" + token + "/" + sessionToken + "/note.pdf"
		fileInfo, err := os.Stat(filePath)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			render.Text(404, "Bad sessionToken.", )
			return
		}

		openFile, err := os.Open(filePath)
		defer openFile.Close()
		if err != nil {
			render.Text(404, "File not found.")
			return
		}

		FileHeader := make([]byte, 512)

		openFile.Read(FileHeader)

		FileContentType := http.DetectContentType(FileHeader)

		//Get the file size
		FileStat, _ := openFile.Stat()                     //Get info from file
		FileSize := strconv.FormatInt(FileStat.Size(), 10) //Get file size as a string

		//Send the headers
		writer.Header().Set("Content-Disposition", "attachment; filename="+fileInfo.Name())
		writer.Header().Set("Content-Type", FileContentType)
		writer.Header().Set("Content-Length", FileSize)

		openFile.Seek(0, 0)
		io.Copy(writer, openFile)
		return
	})

	/*m.Get("/git/:id/latex", func(params martini.Params, render render.Render, request *http.Request, log *log.Logger) {
		token := params["id"]
		exist, _ := checkToken(token)
		if !exist {
			render.Text(404, "Bad id")
			return
		}

		request.ParseForm()
		pathNote := request.Form.Get("pathNote")

		var dir, _ = os.Getwd()
		cmd := exec.Command("/bin/sh", "-c", "docker run -v "+dir+"/tmp/note/:/root/note/ terehovk/diploma-latex:0.1 /root/run.sh note.tex")

		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("cmd.Run() failed with %s\n", err)
			render.Text(500, "error: " + err.Error())
		}
		//log.Printf("combined out:\n%s\n", string(out))
		render.Text(200, "latex:" + string(out))
	})*/

	m.Run()
}

func tryChangePreambleFont(pathDir string) {
	log.Println("tryChangePreambleFont:" + pathDir)

	preambleFile := pathDir + "/preamble.tex"
	fileInfo, err := os.Stat(preambleFile)
	if os.IsNotExist(err) {
		log.Println("File preamble doesn't exist: " + preambleFile)
		return
	}
	log.Println("Try replace win")

	data, err := ioutil.ReadFile(preambleFile)
	if err != nil {
		log.Println("Can't open")
		return
	}

	var re = regexp.MustCompile(`(^|\n)\s*\\input{fonts_windows}.+\n`)
	newString := "\n\\input{fonts_linux"
	newData := re.ReplaceAll(data, []byte(newString))

	ioutil.WriteFile(preambleFile, newData, fileInfo.Mode())
}

func checkToken(token string) (bool, string) {
	pubkeyPath := "./keys/" + token + "/id_rsa.pub"
	_, err := os.Stat(pubkeyPath)
	return !os.IsNotExist(err), pubkeyPath
}

func generateRSA(token string) string {
	os.MkdirAll("./keys/"+token, 0755)
	savePrivateFileTo := "./keys/" + token + "/id_rsa"
	savePublicFileTo := "./keys/" + token + "/id_rsa.pub"
	bitSize := 4096

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	err = writeKeyToFile(privateKeyBytes, savePrivateFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile([]byte(publicKeyBytes), savePublicFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}

	return string(publicKeyBytes)
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}
