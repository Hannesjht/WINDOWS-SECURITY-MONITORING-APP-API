[Setup]
AppName=AI Security Monitor Portable
AppVersion=2.0.0
DefaultDirName={sd}\AISecurityPortable
DisableDirPage=no
DisableProgramGroupPage=yes
DisableWelcomePage=yes
OutputBaseFilename=AI-Security-Monitor-Portable
Compression=lzma2/ultra
SolidCompression=yes
CreateAppDir=yes
Uninstallable=no
PrivilegesRequired=lowest
WizardImageFile=splash.bmp
WizardImageStretch=yes

[Files]
Source: "launcher.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "jre\*"; DestDir: "{app}\jre"; Flags: recursesubdirs
Source: "ai-security-2.0.0.jar"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "splash.bmp"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autodesktop}\AI Security Monitor"; Filename: "{app}\launcher.exe"
Name: "{userprograms}\AI Security Monitor"; Filename: "{app}\launcher.exe"

[Run]
Filename: "powershell.exe"; Parameters: "-Command ""$shortcut=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath(''Desktop'') + ''\AI Security Monitor.lnk''); $shortcut.TargetPath=''{app}\launcher.exe''; $shortcut.WorkingDirectory=''{app}''; $shortcut.Save()"""; Flags: runhidden
Filename: "{app}\launcher.exe"; Description: "Launch AI Security Monitor"; Flags: postinstall nowait skipifsilent
