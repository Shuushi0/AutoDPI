package i18n

import "golang.org/x/sys/windows"

var procUILang = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

// systemLanguage is the Windows display language of the user.
func systemLanguage() string {
	id, _, _ := procUILang.Call()
	if id&0x3FF == 0x1F { // LANG_TURKISH
		return "tr"
	}
	return "en"
}
