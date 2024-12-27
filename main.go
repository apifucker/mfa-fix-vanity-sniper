package main

import (
    "bytes"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "os/exec"
    "os/signal"
    "runtime"
    "sync"
    "syscall"
    "time"

    "github.com/gorilla/websocket"
)
 
type Config struct {
    Token        string `json:"token"`
    Password     string `json:"password"`
    GuildID      string `json:"guild_id"`
    NewVanityURL string `json:"new_vanity_url"`
    WebhookURL   string `json:"webhook_url"`  
}

 
type MFAPayload struct {
    Ticket string `json:"ticket"`
    Type   string `json:"mfa_type"`
    Data   string `json:"data"`
}

 
type MFAResponse struct {
    Token string `json:"token"`
}

 
type VanityResponse struct {
    MFA struct {
        Ticket string `json:"ticket"`
    } `json:"mfa"`
}

 
type GatewayPayload struct {
    Op int             `json:"op"`
    D  json.RawMessage `json:"d"`
    S  int             `json:"s,omitempty"`
    T  string          `json:"t,omitempty"`
}

 
type IdentifyPayload struct {
    Token      string            `json:"token"`
    Intents    int               `json:"intents"`
    Properties map[string]string `json:"properties"`
}
 
type ReadyEvent struct {
    V      int     `json:"v"`
    User   User    `json:"user"`
    Guilds []Guild `json:"guilds"`
}

 
type User struct {
    ID            string `json:"id"`
    Username      string `json:"username"`
    Discriminator string `json:"discriminator"`
}
 
type Guild struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}
 
type GuildUpdateEvent struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}
 
type GuildDeleteEvent struct {
    ID string `json:"id"`
}
 
var (
    httpClient     *http.Client
    socket         *websocket.Conn
    mu             sync.Mutex
    sequence       int
    reconnectChan  = make(chan struct{})
    mfaToken       string 
    mfaRetryCount  int    
    maxMfaRetries  = 3    
    guilds         = make(map[string]string)
    config         Config
    webhookURL     string
)

 
const (
    DiscordGatewayURL    = "wss://gateway.discord.gg/?v=10&encoding=json"
    OpcodeDispatch       = 0
    OpcodeHeartbeat      = 1
    OpcodeIdentify       = 2
    OpcodeReconnect      = 7
    OpcodeInvalidSession = 9
    OpcodeHello          = 10
    OpcodeHeartbeatAck   = 11
    Intents              = 1 << 0 
)

 
func clearConsole() {
    var cmd *exec.Cmd
    switch runtime.GOOS {
    case "windows":
        cmd = exec.Command("cmd", "/c", "cls")
    default:
        cmd = exec.Command("clear")
    }
    cmd.Stdout = os.Stdout
    cmd.Run()
}

 
func Input(message string) string {
    fmt.Print(message)
    var input string
    fmt.Scanln(&input)
    return input
}

 
func loadConfig(filename string) (*Config, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }

    var config Config
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to parse config file: %w", err)
    }

    return &config, nil
}

 
func sendWebhook(message string) error {
    if webhookURL == "" {
        return fmt.Errorf("webhook URL is not configured")
    }

    payload := map[string]string{
        "content": message,
    }

    jsonData, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("failed to marshal webhook payload: %w", err)
    }

    req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")

    resp, err := httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("failed to send webhook: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("webhook responded with status code %d: %s", resp.StatusCode, string(bodyBytes))
    }

    return nil
}

 
func connectGateway() error {
    dialer := websocket.Dialer{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, 
        },
    }
    var err error
    socket, _, err = dialer.Dial(DiscordGatewayURL, nil)
    if err != nil {
        return fmt.Errorf("failed to connect to gateway: %w", err)
    }
    log.Println("Connected to Discord Gateway.")
    return nil
}
 
func identifyGateway(token string) error {
    identify := IdentifyPayload{
        Token:   token,
        Intents: Intents,
        Properties: map[string]string{
            "$os":      "linux",
            "$browser": "go",
            "$device":  "go",
        },
    }

    payloadData, err := json.Marshal(identify)
    if err != nil {
        return fmt.Errorf("failed to marshal identify payload: %w", err)
    }

    gatewayPayload := GatewayPayload{
        Op: OpcodeIdentify,
        D:  payloadData,
    }

    if err := socket.WriteJSON(gatewayPayload); err != nil {
        return fmt.Errorf("failed to send identify payload: %w", err)
    }

    log.Println("Identify payload sent.")
    return nil
}
 
func handleMessages(token, guildID, newURL, pass string) {
    for {
        _, message, err := socket.ReadMessage()
        if err != nil {
            log.Printf("Error reading message from WebSocket: %v", err)
            reconnectChan <- struct{}{}
            return
        }

        var payload GatewayPayload
        if err := json.Unmarshal(message, &payload); err != nil {
            log.Printf("Error decoding JSON: %v", err)
            continue
        }
        var data map[string]interface{}
        err = json.Unmarshal(message, &data)
        if err != nil {
            log.Println("Error decoding JSON:", err)
            continue
        }
        eventType, _ := data["t"].(string)
        switch payload.Op {
        case OpcodeDispatch:
            switch eventType {
            case "READY":
                var ready ReadyEvent
                if err := json.Unmarshal(payload.D, &ready); err != nil {
                    log.Printf("Error unmarshalling READY event: %v", err)
                    continue
                }
                log.Printf("Received READY event for user: %s#%s", ready.User.Username, ready.User.Discriminator)
                guildList := data["d"].(map[string]interface{})["guilds"].([]interface{})
                for _, guild := range guildList {
                    guildMap := guild.(map[string]interface{})
                    if vanityURLCode, exists := guildMap["vanity_url_code"].(string); exists {
                        guilds[guildMap["id"].(string)] = vanityURLCode
                        log.Println(vanityURLCode)
                    }
                }
            case "GUILD_UPDATE":
                guildIDxxd := data["d"].(map[string]interface{})["guild_id"].(string)
                guild, ok := guilds[guildIDxxd]
                if ok {
                    var guildUpdate GuildUpdateEvent
                    if err := json.Unmarshal(payload.D, &guildUpdate); err != nil {
                        log.Printf("Error unmarshalling GUILD_UPDATE event: %v", err)
                        continue
                    }
                    log.Printf("Received GUILD_UPDATE for Guild ID: %s, New Name: %s", guildUpdate.ID, guildUpdate.Name)

                    go getURL(token, guildID, guild, pass, false)
                }
            case "GUILD_DELETE":
                var guildDelete GuildDeleteEvent
                if err := json.Unmarshal(payload.D, &guildDelete); err != nil {
                    log.Printf("Error unmarshalling GUILD_DELETE event: %v", err)
                    continue
                }
                log.Printf("Received GUILD_DELETE for Guild ID: %s", guildDelete.ID)
 
            }
        case OpcodeHello:
            var hello struct {
                HeartbeatInterval int `json:"heartbeat_interval"`
            }
            if err := json.Unmarshal(payload.D, &hello); err != nil {
                log.Printf("Error unmarshalling HELLO payload: %v", err)
                continue
            }
            go startHeartbeat(hello.HeartbeatInterval)
        case OpcodeHeartbeatAck:
            log.Println("Heartbeat acknowledged.")
        case OpcodeReconnect:
            log.Println("Received RECONNECT opcode, reconnecting...")
            reconnectChan <- struct{}{}
            return
        case OpcodeInvalidSession:
            log.Println("Received INVALID_SESSION opcode, re-identifying...")
            if err := identifyGateway(token); err != nil {
                log.Printf("Error re-identifying: %v", err)
            }
        default:
        }

        if payload.S != 0 {
            mu.Lock()
            sequence = payload.S
            mu.Unlock()
        }
    }
}

func startHeartbeat(interval int) {
    ticker := time.NewTicker(time.Duration(interval) * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            mu.Lock()
            hbSeq := sequence
            mu.Unlock()

            heartbeatPayload := GatewayPayload{
                Op: OpcodeHeartbeat,
                D:  json.RawMessage(fmt.Sprintf("%d", hbSeq)),
            }

            if err := socket.WriteJSON(heartbeatPayload); err != nil {
                log.Printf("Error sending heartbeat: %v", err)
                reconnectChan <- struct{}{}
                return
            }
            log.Println("Heartbeat sent.")
        }
    }
}

func reconnect(token, guildID, newURL, pass string) {
    for {
        select {
        case <-reconnectChan:
            log.Println("Attempting to reconnect to Discord Gateway...")
            if socket != nil {
                socket.Close()
            }

            time.Sleep(5 * time.Second) 

            if err := connectGateway(); err != nil {
                log.Printf("Reconnection failed: %v", err)
                continue
            }

            if err := identifyGateway(token); err != nil {
                log.Printf("Re-identification failed: %v", err)
                continue
            }

            go handleMessages(token, guildID, newURL, pass)
        }
    }
}

func sendMFA(token, ticket, pass string) string {
    log.Println("sendMFA: Starting MFA process...")

    payload := MFAPayload{
        Ticket: ticket,
        Type:   "password",
        Data:   pass,
    }

    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        log.Printf("sendMFA Error marshalling to JSON: %s\n", err)
        return "err"
    }

    req, err := http.NewRequest("POST", "https://discord.com/api/v9/mfa/finish", bytes.NewBuffer(jsonPayload))
    if err != nil {
        log.Printf("sendMFA Error creating request: %s\n", err)
        return "err"
    }
    setCommonHeaders(req, token)

    resp, err := httpClient.Do(req)
    if err != nil {
        log.Printf("sendMFA Network error: %s\n", err)
        return "err"
    }
    defer resp.Body.Close()

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("sendMFA Error reading response body: %s\n", err)
        return "err"
    }

    if resp.StatusCode == http.StatusOK {
        var mfaResponse MFAResponse
        err := json.Unmarshal(bodyBytes, &mfaResponse)
        if err != nil {
            log.Printf("sendMFA JSON Error: %s - %s - %d\n", err, string(bodyBytes), resp.StatusCode)
            return "err"
        }
        log.Printf("MFA token received: %s", mfaResponse.Token)
        return mfaResponse.Token
    } else {
        log.Printf("sendMFA Error: %s - %d\n", string(bodyBytes), resp.StatusCode)
        if resp.StatusCode == http.StatusUnauthorized {
            log.Println("sendMFA: Unauthorized. Check if the MFA ticket or password is correct.")
        }
        return "err"
    }
}

func getURL(token, guildID, newURL, pass string, once bool) {
    startTime := time.Now() 

    body := []byte("{\"code\":\"" + newURL + "\"}")

    req, err := http.NewRequest("PATCH", "https://canary.discord.com/api/v7/guilds/"+guildID+"/vanity-url", bytes.NewBuffer(body))
    if err != nil {
        log.Printf("getURL: Error creating request: %v", err)
        return
    }

    setCommonHeaders(req, token)

    mu.Lock()
    currentMfaToken := mfaToken
    mu.Unlock()

    if currentMfaToken != "" {
        req.Header.Set("X-Discord-Mfa-Authorization", currentMfaToken) // Use MFA token
        req.Header.Set("Cookie", "__Secure-recent_mfa="+currentMfaToken) // Use MFA token
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        log.Printf("getURL: Request failed: %v", err)
        return
    }
    defer resp.Body.Close()

    elapsed := time.Since(startTime).Seconds() * 1000
    requestTime := fmt.Sprintf("%.1fms", elapsed)

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("getURL: Error reading response body: %v", err)
        return
    }

    if resp.StatusCode != http.StatusOK {
        if resp.StatusCode == http.StatusUnauthorized {
            log.Println("getURL: Unauthorized, MFA required.")

            mu.Lock()
            if mfaRetryCount >= maxMfaRetries {
                mu.Unlock()
                log.Println("getURL: Maximum MFA attempts reached. Aborting to prevent loop.")
                message := fmt.Sprintf("discord.gg/%s | Failed To Claim | %s", newURL, requestTime)
                if err := sendWebhook(message); err != nil {
                    log.Printf("Failed to send webhook: %v", err)
                }
                return
            }
            mfaRetryCount++
            mu.Unlock()

            var vanityResponse VanityResponse
            err := json.Unmarshal(bodyBytes, &vanityResponse)
            if err != nil {
                log.Printf("getURL: Error unmarshalling vanity response: %s\n", err)
                return
            }

            ticket := vanityResponse.MFA.Ticket
            log.Printf("getURL: MFA Ticket: %s", ticket)

            newMfaToken := sendMFA(token, ticket, pass)
            if newMfaToken == "" || newMfaToken == "err" {
                log.Println("getURL: Failed to obtain MFA token.")
                message := fmt.Sprintf("discord.gg/%s | Failed To Claim | %s", newURL, requestTime)
                if err := sendWebhook(message); err != nil {
                    log.Printf("Failed to send webhook: %v", err)
                }
                return
            }

            mu.Lock()
            mfaToken = newMfaToken
            mu.Unlock()

            log.Println("getURL: Retrying vanity URL update with new MFA token...")
            getURL(token, guildID, newURL, pass, false)

        } else {
            log.Printf("getURL: Request failed: %v - %s", err, string(bodyBytes))
            message := fmt.Sprintf("||@everyone||\n discord.gg/%s | Failed To Claim | %s", newURL, requestTime)
            if err := sendWebhook(message); err != nil {
                log.Printf("Failed to send webhook: %v", err)
            }
        }
    } else {
        log.Printf("Claimed Vanity: %s", newURL)
        message := fmt.Sprintf("||@everyone||\n discord.gg/%s | Vanity Claimed | %s", newURL, requestTime)
        if err := sendWebhook(message); err != nil {
            log.Printf("Failed to send webhook: %v", err)
        }
    }
}

func setCommonHeaders(req *http.Request, token string) {
    req.Header.Set("Authorization", token)
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
        "AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9164 "+
        "Chrome/124.0.6367.243 Electron/30.2.0 Safari/537.36")
    req.Header.Set("X-Super-Properties", "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MTY0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMjI2MzEiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoidHIiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBkaXNjb3JkLzEuMC45MTY0IENocm9tZS8xMjQuMC42MzY3LjI0MyBFbGVjdHJvbi8zMC4yLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjMwLjIuMCIsIm9zX3Nka192ZXJzaW9uIjoiMjI2MzEiLCJjbGllbnRfdnVibF9udW1iZXIiOjUyODI2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==")
    req.Header.Set("X-Discord-Timezone", "Europe/Istanbul")
    req.Header.Set("X-Discord-Locale", "en-US")
    req.Header.Set("X-Debug-Options", "bugReporterEnabled")
    req.Header.Set("Content-Type", "application/json")
}

func main() {
    cfg, err := loadConfig("config.json")
    if err != nil {
        log.Fatalf("Error loading configuration: %v", err)
    }
    config = *cfg

    webhookURL = config.WebhookURL

    if config.Token == "" || config.Password == "" || config.GuildID == "" || config.WebhookURL == "" {
        log.Fatal("Missing required configuration fields: token, password, guild_id, webhook_url")
    }

    httpClient = &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Insecure mode
        },
        Timeout: 10 * time.Second,
    }

    log.Println("Attempting to get MFA ticket...")

    body := []byte("{\"code\":\"" + config.NewVanityURL + "\"}")

    req, err := http.NewRequest("PATCH", "https://canary.discord.com/api/v7/guilds/"+config.GuildID+"/vanity-url", bytes.NewBuffer(body))
    if err != nil {
        log.Fatalf("main: Error creating request: %v", err)
    }

    setCommonHeaders(req, config.Token)

    resp, err := httpClient.Do(req)
    if err != nil {
        log.Fatalf("main: Failed to get MFA ticket: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusUnauthorized {
        bodyBytes, _ := io.ReadAll(resp.Body)
        log.Fatalf("main: Failed to get MFA ticket: %v - %s", err, string(bodyBytes))
    }

    log.Println("MFA ticket obtained successfully, processing response...")

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Fatalf("main: Error reading response body: %v", err)
    }

    var vanityResponse VanityResponse
    if err := json.Unmarshal(bodyBytes, &vanityResponse); err != nil {
        log.Fatalf("main: Failed to process response: %s", err)
    }

    ticket := vanityResponse.MFA.Ticket
    log.Printf("MFA Ticket: %s", ticket)

    log.Println("Starting MFA process...")

    mfaTokenObtained := sendMFA(config.Token, ticket, config.Password)
    if mfaTokenObtained == "" || mfaTokenObtained == "err" {
        log.Fatalf("main: Failed to obtain MFA token.")
    } else {
        log.Printf("MFA token obtained successfully: %s", mfaTokenObtained)
    }

   
    mu.Lock()
    mfaToken = mfaTokenObtained
    mfaRetryCount = 0 
    mu.Unlock()

    log.Println("Updating vanity URL...")
 
    log.Println("Initial vanity URL update attempted.")

 
    if err := connectGateway(); err != nil {
        log.Fatalf("Failed to connect to Discord Gateway: %v", err)
    }

    if err := identifyGateway(config.Token); err != nil {
        log.Fatalf("Failed to identify to Discord Gateway: %v", err)
    }

    go handleMessages(config.Token, config.GuildID, config.NewVanityURL, config.Password)
    go reconnect(config.Token, config.GuildID, config.NewVanityURL, config.Password)
 
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
    clearConsole()
    log.Println("Bot is running. Listening to Discord events...")

 
    <-stop
    log.Println("Shutting down gracefully...")
    if socket != nil {
 
        socket.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
        socket.Close()
    }
    log.Println("Shutdown complete.")
}
