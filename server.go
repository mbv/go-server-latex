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
)

func main() {
	m := martini.Classic()

	m.Use(render.Renderer(render.Options{
		Directory:  "templates",
		Extensions: []string{".html"},
	}))

	m.Get("/", func(render render.Render, log *log.Logger) {
		render.HTML(200, "index", nil)
	})

	m.Post("/upload", func(r *http.Request) (int, string) {
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
		var dir, _ = os.Getwd()
		return 200, "unzipped" + dir
	})

	m.Get("/latex", func(render render.Render, log *log.Logger) (int, string) {
		var dir, _ = os.Getwd()
		cmd := exec.Command("/bin/sh", "-c", "docker run -v "+dir+"/tmp/note/:/root/note/ terehovk/diploma-latex:0.1 /root/run.sh note.tex")

		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("cmd.Run() failed with %s\n", err)
			return 500, "error: " + err.Error()
		}
		//log.Printf("combined out:\n%s\n", string(out))
		return 200, "latex:" + string(out)
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
	})

	m.Run()
}
