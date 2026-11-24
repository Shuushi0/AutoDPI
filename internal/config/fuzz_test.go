package config

import (
	"encoding/json"
	"testing"
)

// What Parse accepts is what the settings page writes back and the daemon
// reads again at its next start: it must still be accepted then.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"engines":["tlsrec","ciadpi"],"doh_servers":["1.1.1.1","dns.google"],"max_conn":8192,"language":"TR"}`))
	f.Add([]byte(`{"local_domains":["corp.example"],"update_check_hours":24,"auto_update":false,"hedge_ms":300}`))
	f.Add([]byte(`{"ciadpi_args":"-r 1+s --oob 1","escalate_on_silence":true,"dns_takeover":false}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Parse(b)
		if err != nil {
			return
		}
		c.Warnings = nil
		out, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("an accepted config does not marshal: %v", err)
		}
		if _, err := Parse(out); err != nil {
			t.Fatalf("an accepted config is refused once written back: %v\nin:  %s\nout: %s", err, b, out)
		}
	})
}
