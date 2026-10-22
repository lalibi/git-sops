package setup

import (
	"strings"
	"testing"

	"github.com/lalibi/git-sops/internal/config"
)

func TestGeneratedCommitMessagesDescribePathsAndRecipients(t *testing.T) {
	specs, err := config.BuildSpecs(t.TempDir(), []string{"secrets/", "Web.config", "src/Worker/service-secrets.txt"})
	if err != nil {
		t.Fatal(err)
	}
	want := "chore(git-sops): 🔐 Configure transparent file encryption\n\nProtect the following paths:\n- secrets/\n- Web.config\n- src/Worker/service-secrets.txt\n"
	if got := generatedCommitMessage("init", specs, nil); got != want {
		t.Fatalf("init message = %q", got)
	}
	for _, command := range []string{"protect", "unprotect", "add-recipient", "remove-recipient", "migrate-git-crypt"} {
		got := generatedCommitMessage(command, specs, []string{"age1publicrecipient"})
		if !strings.HasPrefix(got, "chore(git-sops): ") || !strings.Contains(got, "\n\n") {
			t.Errorf("%s message has no conventional title/body: %q", command, got)
		}
		for _, path := range []string{"secrets/", "Web.config", "src/Worker/service-secrets.txt"} {
			if !strings.Contains(got, "- "+path+"\n") {
				t.Errorf("%s omits path %s", command, path)
			}
		}
		if strings.HasSuffix(command, "recipient") && !strings.Contains(got, "- age1publicrecipient\n") {
			t.Errorf("%s omits changed public recipient", command)
		}
	}
	if got := generatedCommitMessage("init", nil, nil); !strings.Contains(got, "No paths are protected.") {
		t.Fatalf("empty policy message = %q", got)
	}
}

func TestValidateCommitOptions(t *testing.T) {
	for _, options := range []Options{{Commit: true, NoStage: true}, {Message: "custom"}, {Commit: true, Message: " \n"}} {
		if err := validateCommitOptions(options); err == nil {
			t.Fatalf("accepted incompatible options: %+v", options)
		}
	}
	for _, options := range []Options{{}, {Commit: true}, {Commit: true, Message: "custom"}, {NoStage: true}} {
		if err := validateCommitOptions(options); err != nil {
			t.Fatalf("rejected valid options %+v: %v", options, err)
		}
	}
}
