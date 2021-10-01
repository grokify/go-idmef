package unmarshal

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/grokify/go-idmef"
	"github.com/grokify/go-idmef/testdata"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var xmlExampleTests = []struct {
	xmlFile string
	goMsg   func() *idmef.Message
}{
	{"example_dos_pingofdeath-attack.xml", testdata.ExampleAlertPingOfDeathAttack},
	{"example_dos_teardrop-attack.xml", testdata.ExampleAlertTeardropAttack},
	{"example_port-scanning_connection-to-disallowed-service.xml", testdata.ExamplePortScanningDisallowedService},
	{"example_port-scanning_simple-port-scanning.xml", testdata.ExamplePortScanningSimple},
	{"example_local-attacks_file-modification.xml", testdata.ExampleLocalAttacksFileModification},
	{"example_analyzer-assessments.xml", testdata.ExampleAlertAnalyzerAssessment},
	{"example_system-policy-violation.xml", testdata.ExampleSystemPolicyViolation},
	{"example_correlated-alerts.xml", testdata.ExampleAlertCorrelatedAlerts},
}

// TestExampleAlerts ensures parse sample correct.
func TestExampleAlerts(t *testing.T) {
	for _, tt := range xmlExampleTests {
		compare(t, filepath.Join("../testdata/", tt.xmlFile), tt.goMsg)
	}
}

func compare(t *testing.T, testFileXML string, sampleMessage func() *idmef.Message) {
	mGo := sampleMessage()

	mFile, err := ReadFile(testFileXML)
	if err != nil {
		t.Errorf("unmarshal.ParseFile(\"%s\") error[%s]",
			testFileXML, err.Error())
	}

	xGo, err := mGo.Bytes("", "  ")
	if err != nil {
		t.Errorf("xml.Unmarshal Marshal error[%s]", err.Error())
	}

	xFile, err := mFile.Bytes("", "  ")
	if err != nil {
		t.Errorf("xml.Unmarshal Marshal error[%s]", err.Error())
	}
	if string(xGo) != string(xFile) {
		fmt.Println(string(xGo))
		fmt.Println(string(xFile))

		fmt.Println(">>> DIFF1 >>>")
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(xGo), string(xFile), false)
		fmt.Println(dmp.DiffPrettyText(diffs))
		fmt.Println("<<< DIFF1 <<<")
		fmt.Println(">>> DIFF2 >>>")

		dmp2 := diffmatchpatch.New()
		diffs2 := dmp2.DiffMain(string(xFile), string(xGo), false)
		fmt.Println(dmp2.DiffPrettyText(diffs2))
		fmt.Println("<<< DIFF2 <<<")

		t.Errorf("Go does not match test file [%s]", testFileXML)
	}
}
