package unmarshal

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/grokify/go-idmef"
)

// TestSampleAlert ensures parse sample correct.
func TestSampleAlert(t *testing.T) {
	samp := idmef.SampleAlert()
	fdata, err := os.ReadFile("testdata/example_pingofdeath.xml")
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
	if !reflect.DeepEqual(samp, alertFile) {
		t.Error("idmef.SampleAlert() does not match")
		new, err := xml.MarshalIndent(alertFile, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(new))
	}
}
