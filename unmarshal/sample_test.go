package unmarshal

import (
	"fmt"
	"testing"

	"github.com/grokify/go-idmef/testdata"
)

const testFileXML = "../testdata/example_pingofdeath.xml"

// TestSampleAlert ensures parse sample correct.
func TestSampleAlert(t *testing.T) {
	sampleGo := testdata.SampleAlert()

	sampleFile, err := ReadFile(testFileXML)
	if err != nil {
		t.Errorf("unmarshal.ParseFile(\"%s\") error[%s]",
			testFileXML, err.Error())
	}

	s1, err := sampleGo.Bytes("", "  ")
	if err != nil {
		t.Errorf("xml.Unmarshal Marshal error[%s]",
			err.Error())
	}
	s2, err := sampleFile.Bytes("", "  ")
	if err != nil {
		t.Errorf("xml.Unmarshal Marshal error[%s]",
			err.Error())
	}
	if string(s1) != string(s2) {
		fmt.Println(string(s1))
		fmt.Println(string(s2))
		t.Error("idmef.SampleAlert() does not match test file.")
	}
}
