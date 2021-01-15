Dim MSXML, EL, key, pw
Set SHA256 = CreateObject("System.Security.Cryptography.SHA256Managed")
Set MSXML = CreateObject("MSXML2.DOMDocument")
Set objShell = CreateObject("WScript.Shell")
Set enc = CreateObject("System.Text.UTF8Encoding")

key = InputBox("Enter Secret Key")
If key <> InputBox("Enter Key Again") Then
	Wscript.Quit
End If

Do While True
	pw = InputBox("Enter Name (or exit)")
	If pw = "exit" Then
		Wscript.Quit
	End If
	SHA256.ComputeHash_2(enc.Getbytes_4(pw & key))
	Set EL = MSXML.CreateElement("tmp")
	EL.DataType = "bin.base64"
	EL.NodeTypedValue = SHA256.Hash
	WScript.Sleep(2000)
	pw = Replace(Replace(EL.Text, "+", ""), "/", "")
	text = Mid(pw, 1, 8) & "-" & Mid(pw, 9, 8)
        i = 1
        Do While (i < 18)
            objShell.sendKeys(Mid(text,i,1))
            WScript.Sleep(30)
            objShell.sendKeys("+")
            i=i+1
        Loop
Loop

