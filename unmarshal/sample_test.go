package unmarshal

import (
	"fmt"
	"testing"

	"github.com/grokify/go-idmef"
	"github.com/grokify/go-idmef/testdata"
)

const (
	testFileXML = "../testdata/example_pingofdeath.xml"
)

// TestSampleAlert ensures parse sample correct.
func TestSampleAlert(t *testing.T) {
	compare(t, testFileXML, testdata.SampleAlert)
	compare(t, "../testdata/example_teardrop-attack.xml", testdata.SampleAlertTeardropAttack)
	/*
		mGo := testdata.SampleAlert()

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
			t.Error("testdata.SampleAlert() does not match test file.")
		}
	*/

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
		t.Error("testdata.SampleAlert() does not match test file.")
	}
}
