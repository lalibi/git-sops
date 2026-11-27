package sopsx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// CheckRecipients inspects public wrapping-key metadata without a decryption key.
// Group policies use only native age recipients; other key backends would grant
// access outside the declared group.
func CheckRecipients(path string, blob []byte, want []string) error {
	keys, err := CipherRecipients(path, blob)
	if err != nil {
		return err
	}
	if len(want) == 0 || !slices.Equal(keys, want) {
		return errors.New("encrypted recipients differ from the effective group")
	}
	return nil
}

// CipherRecipients returns the actual age recipients, including during checkout
// when the policy in the working tree may still belong to the previous commit.
func CipherRecipients(path string, blob []byte) ([]string, error) {
	mismatch := errors.New("expected consistent age-only SOPS key metadata")
	format := TypesFor(path).Encrypted
	if format == "dotenv" || format == "ini" {
		var keys []string
		inSops := false
		for line := range strings.SplitSeq(string(blob), "\n") {
			line = strings.TrimSpace(line)
			if format == "ini" {
				if strings.HasPrefix(line, "[") {
					inSops = line == "[sops]"
					continue
				}
				if !inSops {
					continue
				}
			}
			name, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			name = strings.TrimSpace(name)
			if format == "dotenv" {
				name, ok = strings.CutPrefix(name, "sops_")
				if !ok {
					continue
				}
			}
			backend, _, nested := strings.Cut(name, "__")
			if nested && backend != "age" {
				return nil, mismatch
			}
			if strings.HasPrefix(name, "age__list_") && strings.HasSuffix(name, "__map_recipient") {
				keys = append(keys, strings.TrimSpace(value))
			}
		}
		if len(keys) == 0 {
			return nil, mismatch
		}
		slices.Sort(keys)
		return keys, nil
	}
	if format == "json" {
		// Binary archives use a JSON envelope. Skip the large encrypted data
		// field instead of constructing YAML nodes for the whole archive.
		var envelope struct {
			Sops json.RawMessage `json:"sops"`
		}
		if err := json.Unmarshal(blob, &envelope); err != nil {
			return nil, err
		}
		var metadata map[string]yaml.Node
		if err := yaml.Unmarshal(envelope.Sops, &metadata); err != nil {
			return nil, err
		}
		return metadataRecipients(metadata)
	}
	reader := yaml.NewDecoder(bytes.NewReader(blob))
	var recipients []string
	for count := 0; ; count++ {
		var doc struct {
			Sops map[string]yaml.Node `yaml:"sops"`
		}
		err := reader.Decode(&doc)
		if err == io.EOF && count > 0 {
			return recipients, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read SOPS key metadata: %w", err)
		}
		keys, err := metadataRecipients(doc.Sops)
		if err != nil {
			return nil, err
		}
		if count > 0 && !slices.Equal(keys, recipients) {
			return nil, mismatch
		}
		recipients = keys
	}
}

func metadataRecipients(metadata map[string]yaml.Node) ([]string, error) {
	var ageKeys []struct{ Recipient string }
	for field, value := range metadata {
		if field == "age" {
			if err := value.Decode(&ageKeys); err != nil {
				return nil, err
			}
		} else if value.Kind == yaml.AliasNode || ((value.Kind == yaml.SequenceNode || value.Kind == yaml.MappingNode) && len(value.Content) > 0) {
			return nil, errors.New("unexpected key group or backend in SOPS metadata")
		}
	}
	var keys []string
	for _, k := range ageKeys {
		keys = append(keys, k.Recipient)
	}
	slices.Sort(keys)
	if len(keys) == 0 {
		return nil, errors.New("no age recipients in SOPS metadata")
	}
	return keys, nil
}
