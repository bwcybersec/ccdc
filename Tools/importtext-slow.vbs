BrowseForFile = CreateObject("WScript.Shell").Exec( _
    "mshta.exe ""about:<input type=file id=f>" & _
    "<script>resizeTo(0,0);f.click();new ActiveXObject('Scripting.FileSystemObject')" & _
    ".GetStandardStream(1).WriteLine(f.value);close();</script>""" _
  ).StdOut.ReadLine()
Set objShell = CreateObject("WScript.Shell")
Set ObjFso = CreateObject("Scripting.FileSystemObject")
Set f = ObjFso.OpenTextFile(BrowseForFile)
WScript.Sleep(5000)
Do Until f.AtEndOfStream
    StrData = f.ReadLine
    i = 1
    Do While (i <= Len(StrData))
        objShell.sendKeys("{" & Mid(StrData,i,1) & "}")
        objShell.sendKeys("+")
        i=i+1
        WScript.Sleep(1)
    Loop
    WScript.Sleep(100)
    objShell.sendKeys("~")
    WScript.Sleep(100)
Loop
