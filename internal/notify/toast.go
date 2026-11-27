package notify

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"net/url"
	"strings"
	"unicode/utf16"
)

// powershellAUMID is the app identity Windows already knows for PowerShell,
// so toasts work without registering trafficam with the Start menu.
// The installer (separate work) can register a proper "trafficam" identity.
const powershellAUMID = `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`

func xmlText(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func xmlAttr(s string) string {
	return strings.NewReplacer(`"`, "&quot;", "'", "&apos;").Replace(xmlText(s))
}

// isLocalURL allows only the trafficam window on this computer.
func isLocalURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.User == nil
}

// toastXML builds the Windows toast. Text is XML-escaped and on one line.
func toastXML(n Note) string {
	launch, scenario := "", ""
	if n.OpenURL != "" && isLocalURL(n.OpenURL) {
		launch = ` activationType="protocol" launch="` + xmlAttr(n.OpenURL) + `"`
	}
	if n.Urgency == Critical {
		scenario = ` scenario="reminder"` // stays until dismissed
	}
	var b strings.Builder
	b.WriteString(`<toast` + launch + scenario + `><visual><binding template="ToastGeneric">`)
	b.WriteString(`<text>` + xmlText(Clean(n.Title, 120)) + `</text>`)
	for _, line := range strings.SplitN(n.Body, "\n", 3) {
		if line = Clean(line, 200); line != "" {
			b.WriteString(`<text>` + xmlText(line) + `</text>`)
		}
	}
	b.WriteString(`</binding></visual>`)
	if n.Urgency == Critical {
		b.WriteString(`<actions><action content="Dismiss" arguments="dismiss" activationType="system"/></actions>`)
	}
	b.WriteString(`</toast>`)
	return b.String()
}

// toastScript is the PowerShell that shows the toast. The XML sits in a
// single-quoted here-string (no variable expansion); it cannot end the string
// early because it is a single line and never starts a line with '@.
func toastScript(n Note) string {
	return `$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml(@'
` + toastXML(n) + `
'@)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('` + powershellAUMID + `').Show([Windows.UI.Notifications.ToastNotification]::new($x))
`
}

// encodePS encodes a script for powershell -EncodedCommand (UTF-16LE, base64).
func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return base64.StdEncoding.EncodeToString(b)
}
