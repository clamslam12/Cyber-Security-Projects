#create an object to watch file system
    $filewatcher = New-Object System.IO.FileSystemWatcher
    #directory path to monitor
    $filewatcher.Path = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
    #watch all files
    $filewatcher.Filter = "*.*"
    #include subdirectories
    $filewatcher.IncludeSubdirectories = $true
    $filewatcher.EnableRaisingEvents = $true  
 
#if event is raised...
    $writeaction = { $path = $Event.SourceEventArgs.FullPath
                $changeType = $Event.SourceEventArgs.ChangeType
                $logline = "$(Get-Date), $changeType, $path"
                Add-content "C:\Users\Administrator\Desktop\logFile.txt" -value $logline
              }    
#events to be monitored
 
    Register-ObjectEvent $filewatcher "Created" -Action $writeaction
    Register-ObjectEvent $filewatcher "Changed" -Action $writeaction
    Register-ObjectEvent $filewatcher "Deleted" -Action $writeaction
    Register-ObjectEvent $filewatcher "Renamed" -Action $writeaction
    #wait for 5 mins between logs
    while ($true) {Start-Sleep -s 300}