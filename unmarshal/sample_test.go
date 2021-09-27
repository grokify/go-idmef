package unmarshal

import (
	"encoding/xml"
	"fmt"
	"os"
	"testing"

	"github.com/grokify/go-idmef/testdata"
)

// TestSampleAlert ensures parse sample correct.
func TestSampleAlert(t *testing.T) {
	samp := testdata.SampleAlert()
	fdata, err := os.ReadFile("../testdata/example_pingofdeath.xml")
	if err != nil {
		t.Errorf("idmef.TestSampleAlert os.ReadFile error[%s]",
			err.Error())
	}
	alertFileUnm := Message{}
	err = xml.Unmarshal(fdata, &alertFileUnm)
	if err != nil {
		t.Errorf("xml.Unmarshal Unmarshal error[%s]",
			err.Error())
	}
	alertFile := alertFileUnm.Common()

	s1, err := samp.Bytes("", "  ")
	if err != nil {
		t.Errorf("xml.Unmarshal Marshal error[%s]",
			err.Error())
	}
	s2, err := alertFile.Bytes("", "  ")
	if err != nil {
		t.Errorf("xml.Unmarshal Marshal error[%s]",
			err.Error())
	}
	if string(s1) != string(s2) {
		fmt.Println(string(s1))
		fmt.Println(string(s2))
		t.Error("idmef.SampleAlert() does not match test file.")
	}

	/*
		if !reflect.DeepEqual(samp, alertFile) {
			t.Error("idmef.SampleAlert() does not match")
			new, err := xml.MarshalIndent(alertFile, "", "  ")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(new))
		}*/
}
