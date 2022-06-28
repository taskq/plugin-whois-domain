package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
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
	WhoisServer string              `json:"whois_server"`
	Domain      string              `json:"domain"`
	Whois       map[string][]string `json:"whois"`
}

func SubmitWhoisQuery(key string, whois_server string) (result map[string][]string, err error) {

	resolved_address, err := net.ResolveTCPAddr("tcp4", whois_server+":43")
	if err != nil {
		log.Error().Err(err).Msgf("Error while resolving whois server address")
		return nil, err
	}

	log.Debug().
		Str("whois_server", resolved_address.String()).
		Msgf("Resolved whois server address")

	conn, err := net.Dial("tcp", resolved_address.String())
	if err != nil {
		log.Error().Err(err).Msgf("Error while connecting to whois server")
		return nil, err
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
			return nil, err
		}

		result_raw = append(result_raw, strings.Trim(str, " \r\n"))
	}

	object_regex := regexp.MustCompile("^(?P<leadin_spacing>[\\s]+)?(?P<key>[\\w\\s]+?):(?P<table_spacing>\\s+)?(?P<value>.*)$")

	log.Info().
		Int("result_raw size", len(result_raw)).
		Msgf("Whois server response lines")

	struct_result := make(map[string][]string)

	for _, object := range result_raw {

		object_match := object_regex.FindStringSubmatch(object)

		log.Debug().
			Int("object_match size", len(object_match)).
			Strs("object_match", object_match).
			Msgf("Matched whois response line")

		if len(object_match) < 4 {
			log.Warn().
				Int("object_match size", len(object_match)).
				Strs("object_match", object_match).
				Msgf("Skipping poorly matched line")
			continue
		}

		key := object_match[2]
		value := object_match[4]

		log.Debug().
			Str("key", key).
			Str("value", value).
			Msgf("Object type attribute regexp match")

		struct_result[key] = append(struct_result[key], value)
	}

	// result_pretty, err := json.Marshal(struct_result)
	// if err != nil {
	// 	log.Error().Err(err).Msgf("Couldn't prettify result")
	// }

	// result_pretty_string := string(result_pretty)

	return struct_result, nil

}

func ExecCommand(payload []byte, configurationRaw interface{}) (result []byte, err error) {

	payloadParsed := PayloadStruct{}
	JSONDecoder := json.NewDecoder(bytes.NewReader(payload))

	err = JSONDecoder.Decode(&payloadParsed)
	if err != nil {
		log.Error().Err(err).Msgf("Error while reading payload")
		return nil, fmt.Errorf("Error while reading payload: %v", err)
	}

	log.Info().
		Str("plugin", PluginName).
		Msgf("payloadParsed: %+v", payloadParsed)

	whoisResult, err := SubmitWhoisQuery(payloadParsed.Domain, payloadParsed.WhoisServer)
	if err != nil {
		log.Error().Err(err).Msgf("Error while submitting whois query")
		return nil, fmt.Errorf("Error while submitting whois query: %v", err)
	}

	log.Info().
		Int("result_items", len(whoisResult)).
		Msgf("Whois query submitted")

	outputPayload := OutputPayloadStruct{
		Domain:      payloadParsed.Domain,
		WhoisServer: payloadParsed.WhoisServer,
		Whois:       whoisResult,
	}

	outputPayloadJSON, err := json.Marshal(outputPayload)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	log.Info().
		Str("plugin", PluginName).
		Bytes("payload", payload).
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
