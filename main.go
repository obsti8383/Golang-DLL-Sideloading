package main

import (
	"golang.org/x/sys/windows"
)

func main() {
	// Works by correctly calling SetDLLDirectory with empty string
	SaferDLLLoading()

	// also seems to work,
	// only available on Win8+
	//windows.SetDefaultDllDirectories(0x00000800)

	// does not work, Go lib seems to not convert
	// empty strings correctly.
	//windows.SetDllDirectory("")

	// Load DLL for demo
	windows.LoadLibrary("dwmapi.dll")
	//windows.LoadLibrary("dwmapi.dll")
}
