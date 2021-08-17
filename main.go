package main

import (
	"bytes"
	"crypto/sha512"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const IMAGE_ID = 304052 // Ubuntu 20.04 64-bit (template)

type ErrorResponse struct {
	Error string `json:"error"`
}

type GetIPResponse struct {
	IP string `json:"ip"`
}

type NullResponse struct {}

type LunaVolumeCreate struct {
	VolumeID string `json:"volume_id"`
}

type LunaVolumeInfo struct {
	Volume struct {
		Status string `json:"status"`
	} `json:"volume"`
}

type LunaSshkeyAdd struct {
	KeyID string `json:"key_id"`
}

type LunaSshkeyItem struct {
	ID string `json:"id"`
	Value string `json:"value"`
}

type LunaScriptCreate struct {
	ScriptID string `json:"script_id"`
}

type LunaNetworkList struct {
	Networks []struct {
		NetID string `json:"net_id"`
	} `json:"networks"`
}

type LunaFloatingList struct {
	IPs []struct {
		IP string `json:"ip"`
		AttachedType string `json:"attached_type"`
		Region string `json":region"`
	} `json:"ips"`
}

type LunaVmCreate struct {
	VmID string `json:"vm_id"`
}

type LunaDynList struct {
	Dyns map[string]struct{
		ID string `json:"id"`
		Name string `json:"name"`
		IP string `json:"ip"`
	} `json:"dyns"`
}

type LunaVmInfo struct {
	Info struct {
		Status string `json:"status_nohtml"`
	} `json:"info"`
}

func main() {
	scriptBytes, err := ioutil.ReadFile("run.sh")
	if err != nil {
		panic(err)
	}
	script := string(scriptBytes)

	fileServer := http.FileServer(http.Dir("static/"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
	http.HandleFunc("/getip", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		apiID := r.PostForm.Get("api_id")
		apiKey := r.PostForm.Get("api_key")
		ip, err := getFreeFloatingIP(apiID, apiKey, "montreal")
		if err != nil {
			errorResponse(w, r, err.Error())
			return
		}
		if ip == "" {
			err := request(apiID, apiKey, "floating", "add", map[string]string{
				"region": "montreal",
			}, nil)
			if err != nil {
				errorResponse(w, r, err.Error())
				return
			}
			ip, _ = getFreeFloatingIP(apiID, apiKey, "montreal")
			if ip == "" {
				errorResponse(w, r, "failed to get an external IP")
				return
			}
		}
		jsonResponse(w, GetIPResponse{ip})
	})

	http.HandleFunc("/launch", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		apiID := r.PostForm.Get("api_id")
		apiKey := r.PostForm.Get("api_key")
		ip := r.PostForm.Get("ip")
		hostname := r.PostForm.Get("hostname")
		nginxPassword := r.PostForm.Get("nginxPassword")
		tz := r.PostForm.Get("tz")
		sshKey := r.PostForm.Get("sshkey")
		email := r.PostForm.Get("email")
		repository := r.PostForm.Get("repository")
		branch := r.PostForm.Get("branch")
		plan := r.PostForm.Get("plan")

		remoteIP := r.RemoteAddr

		myscript := script
		myscript = strings.Replace(myscript, "[HOSTNAME]", hostname, -1)
		myscript = strings.Replace(myscript, "[IP]", ip, -1)
		myscript = strings.Replace(myscript, "[EMAIL]", email, -1)
		myscript = strings.Replace(myscript, "[NGINXPASSWORD]", nginxPassword, -1)
		myscript = strings.Replace(myscript, "[TZ]", tz, -1)
		myscript = strings.Replace(myscript, "[REPOSITORY]", repository, -1)
		myscript = strings.Replace(myscript, "[BRANCH]", branch, -1)

		var cleanupFuncs []func()
		cleanup := func() {
			for _, f := range cleanupFuncs {
				f()
			}
		}

		// create DNS if desired
		if strings.HasSuffix(hostname, ".lndyn.com") && strings.HasPrefix(hostname, "teslamate") && len(hostname) == 26 {
			err := request(apiID, apiKey, "dns", "dyn-add", map[string]string{
				"name": strings.Split(hostname, ".")[0],
				"ip": ip,
			}, nil)
			if err != nil {
				cleanup()
				errorResponse(w, r, err.Error())
				return
			}
			cleanupFuncs = append(cleanupFuncs, func() {
				var response LunaDynList
				if err := request(apiID, apiKey, "dns", "dyn-list", nil, &response); err != nil {
					log.Printf("warning: error listing dyns for cleanup: %v", err)
					return
				}
				for _, dyn := range response.Dyns {
					if dyn.Name == strings.Split(hostname, ".")[0] || dyn.IP == ip {
						request(apiID, apiKey, "dns", "dyn-remove", map[string]string{"dyn_id": dyn.ID}, nil)
					}
				}
			})
		}

		params := map[string]string{
			"region": "montreal",
			"plan_id": plan,
			"image_id": strconv.Itoa(IMAGE_ID),
			"ip": ip,
			"hostname": hostname,
		}

		log.Printf("[%s] creating vm", remoteIP)

		// add ssh key, if set
		// but check if we can reuse a previously added key first
		if sshKey != "" {
			sshKey = strings.TrimSpace(sshKey)
			var listResponse map[string]json.RawMessage
			err := request(apiID, apiKey, "sshkey", "list", nil, &listResponse)
			if err != nil {
				cleanup()
				errorResponse(w, r, "error listing SSH keys: " + err.Error())
				return
			}
			var foundID string
			for k, msg := range listResponse {
				if k == "success" {
					continue
				}
				var key LunaSshkeyItem
				if err := json.Unmarshal(msg, &key); err != nil {
					continue
				}
				if strings.TrimSpace(key.Value) == sshKey {
					foundID = key.ID
				}
			}

			if foundID == "" {
				var keyResponse LunaSshkeyAdd
				err := request(apiID, apiKey, "sshkey", "add", map[string]string{
					"label": "tmp",
					"sshkey": sshKey,
				}, &keyResponse)
				if err != nil {
					cleanup()
					errorResponse(w, r, "error adding SSH key: " + err.Error())
					return
				}
				foundID = keyResponse.KeyID
			}

			params["key_id"] = foundID
		} else {
			params["set_password"] = "yes"
		}

		// add startup script
		var scriptResponse LunaScriptCreate
		err = request(apiID, apiKey, "script", "create", map[string]string{
			"name": "tmp-teslamate",
			"content": myscript,
		}, &scriptResponse)
		if err != nil {
			cleanup()
			errorResponse(w, r, "error creating startup script: " + err.Error())
			return
		}
		params["scripts"] = scriptResponse.ScriptID
		defer func() {
			request(apiID, apiKey, "script", "delete", map[string]string{
				"script_id": scriptResponse.ScriptID,
			}, nil)
		}()

		// should we set network?
		var networkResponse LunaNetworkList
		request(apiID, apiKey, "network", "list", map[string]string{
			"region": "montreal",
		}, &networkResponse)
		if len(networkResponse.Networks) >= 1 {
			params["net_id"] = networkResponse.Networks[0].NetID
		}

		// create vm
		var vmResponse LunaVmCreate
		err = request(apiID, apiKey, "vm", "create", params, &vmResponse)
		if err != nil {
			cleanup()
			errorResponse(w, r, "error creating VM: " + err.Error())
			return
		}
		done := false
		for i := 0; i < 10; i++ {
			time.Sleep(5*time.Second)
			var infoResponse LunaVmInfo
			err := request(apiID, apiKey, "vm", "info", map[string]string{
				"vm_id": vmResponse.VmID,
			}, &infoResponse)
			if err != nil {
				cleanup()
				errorResponse(w, r, "error waiting for VM: " + err.Error())
				return
			}
			if infoResponse.Info.Status == "Online" {
				done = true
				break
			}
		}
		if !done {
			cleanup()
			errorResponse(w, r, "timed out waiting for VM creation")
			return
		}

		jsonResponse(w, NullResponse{})
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func errorResponse(w http.ResponseWriter, r *http.Request, msg string) {
	log.Printf("[%s] error: %s", r.RemoteAddr, msg)
	jsonResponse(w, ErrorResponse{msg})
}

func jsonResponse(w http.ResponseWriter, x interface{}) {
	bytes, err := json.Marshal(x)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

const LNDYNAMIC_API_URL = "https://dynamic.lunanode.com/api/{CATEGORY}/{ACTION}/"

func request(apiID string, apiKey string, category string, action string, params map[string]string, target interface{}) error {
	if len(apiID) != 16 {
		return fmt.Errorf("API ID should be 16 characters")
	} else if len(apiKey) != 128 {
		return fmt.Errorf("API key should be 128 characters")
	}

	// construct URL
	targetUrl := LNDYNAMIC_API_URL
	targetUrl = strings.Replace(targetUrl, "{CATEGORY}", category, -1)
	targetUrl = strings.Replace(targetUrl, "{ACTION}", action, -1)

	// get raw parameters string
	if params == nil {
		params = make(map[string]string)
	}
	params["api_id"] = apiID
	params["api_partialkey"] = apiKey[:64]
	rawParams, err := json.Marshal(params)
	if err != nil {
		return err
	}

	// HMAC signature with nonce
	nonce := fmt.Sprintf("%d", time.Now().Unix())
	handler := fmt.Sprintf("%s/%s/", category, action)
	hashTarget := fmt.Sprintf("%s|%s|%s", handler, string(rawParams), nonce)
	hasher := hmac.New(sha512.New, []byte(apiKey))
	_, err = hasher.Write([]byte(hashTarget))
	if err != nil {
		return err
	}
	signature := hex.EncodeToString(hasher.Sum(nil))

	// perform request
	values := url.Values{}
	values.Set("handler", handler)
	values.Set("req", string(rawParams))
	values.Set("signature", signature)
	values.Set("nonce", nonce)
	byteBuffer := new(bytes.Buffer)
	byteBuffer.Write([]byte(values.Encode()))
	response, err := http.Post(targetUrl, "application/x-www-form-urlencoded", byteBuffer)
	if err != nil {
		return err
	}
	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	response.Body.Close()

	// decode JSON
	// we first decode into generic response for error checking; then into specific response to return
	var genericResponse struct {
		Success string `json:"success"`
		Error   string `json:"error"`
	}

	err = json.Unmarshal(responseBytes, &genericResponse)

	if err != nil {
		return err
	} else if genericResponse.Success != "yes" {
		if genericResponse.Error != "" {
			return fmt.Errorf(genericResponse.Error)
		} else {
			return fmt.Errorf("backend call failed for unknown reason")
		}
	}

	if target != nil {
		err = json.Unmarshal(responseBytes, target)
		if err != nil {
			return err
		}
	}

	return nil
}

func getFreeFloatingIP(apiID string, apiKey string, region string) (string, error) {
	var response LunaFloatingList
	if err := request(apiID, apiKey, "floating", "list", nil, &response); err != nil {
		return "", err
	}
	for _, ip := range response.IPs {
		if ip.AttachedType == "unattached" && ip.Region == region {
			return ip.IP, nil
		}
	}
	return "", nil
}
