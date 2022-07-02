package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
)

var PluginName string = "WhoisDomain"
var PluginDescription string = "Whois Domain plugin for TaskQ Subscriber"
var BuildVersion string = "0.0.0"

type PayloadStruct struct {
	WhoisServer string `json:"whois_server"`
	Domain      string `json:"domain"`
}

type OutputPayloadStruct struct {
	WhoisServer string `json:"whois_server"`
	Domain      string `json:"domain"`
	Whois       string `json:"whois"`
}

func SubmitWhoisQuery(key string, whois_server string) (result string, err error) {

	resolved_address, err := net.ResolveTCPAddr("tcp4", whois_server+":43")
	if err != nil {
		log.Error().Err(err).Msgf("Error while resolving whois server address")
		return "", err
	}

	log.Debug().
		Str("whois_server", resolved_address.String()).
		Msgf("Resolved whois server address")

	conn, err := net.Dial("tcp", resolved_address.String())
	if err != nil {
		log.Error().Err(err).Msgf("Error while connecting to whois server")
		return "", err
	}

	log.Debug().Msgf("Connected %+v", conn)

	fmt.Fprintf(conn, key+"\r\n")

	connbuf := bufio.NewReader(conn)
	var result_raw []string

	for {

		log.Trace().Msgf("Started looping")

		str, err := connbuf.ReadString('\n')

		if err == nil {
			log.Trace().Msgf("Received a chunk of data")

		} else if err == io.EOF {
			log.Info().Msgf("Reached EOF")
			break

		} else {
			log.Error().Msgf("Error reading conn buffer: %s", err)
			return "", err
		}

		result_raw = append(result_raw, str)
	}

	return strings.Join(result_raw[:], ""), nil

}

func ExecCommand(payload []byte, configurationRaw interface{}) (result []byte, err error) {

	log.Debug().
		Str("plugin", PluginName).
		Int("quotes_num", strings.Count(string(payload), `"`)).
		Str("payload", string(payload)).
		Msgf("Payload accepted")

	payloadParsed := PayloadStruct{}
	JSONDecoder := json.NewDecoder(bytes.NewReader(payload))

	err = JSONDecoder.Decode(&payloadParsed)
	if err != nil {
		log.Error().Err(err).Msgf("Error while reading payload")
		return nil, fmt.Errorf("Error while reading payload: %v", err)
	}

	log.Debug().
		Str("plugin", PluginName).
		Msgf("payloadParsed: %+v", payloadParsed)

	whoisResult, err := SubmitWhoisQuery(payloadParsed.Domain, payloadParsed.WhoisServer)
	if err != nil {
		log.Error().Err(err).Msgf("Error while submitting whois query")
		return nil, fmt.Errorf("Error while submitting whois query: %v", err)
	}

	log.Info().
		Int("result_items", len(whoisResult)).
		Msgf("Whois query result obtained")

	outputPayload := OutputPayloadStruct{
		Domain:      payloadParsed.Domain,
		WhoisServer: payloadParsed.WhoisServer,
		Whois:       whoisResult,
	}

	log.Info().
		Str("plugin", PluginName).
		Int("quotes_num", strings.Count(outputPayload.Whois, `"`)).
		Msgf("payloadParsed: %+v", payloadParsed)

	outputPayloadJSON, err := json.Marshal(outputPayload)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	log.Info().
		Str("plugin", PluginName).
		Bytes("outputPayloadJSON", outputPayloadJSON).
		Int("quotes_num", strings.Count(string(outputPayloadJSON), `"`)).
		Msgf("Preparing to publish a message")

	return outputPayloadJSON, nil
}

func main() {

	returned, err := ExecCommand([]byte(`{"whois_server": "whois.verisign-grs.com"}`), nil)

	log.Info().
		Err(err).
		Str("returned", string(returned)).
		Msgf("Done")

}
