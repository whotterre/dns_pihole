$serverIP = "127.0.0.1"
$serverPort = 5356

# Create UDP client
$udpClient = New-Object System.Net.Sockets.UdpClient
$udpClient.Client.ReceiveTimeout = 5000

try {
    # Build DNS query for google.com (A record)
    $query = [byte[]](
        0x12, 0x34,             # ID
        0x01, 0x00,             # Flags (standard query)
        0x00, 0x01,             # QDCOUNT (1 question)
        0x00, 0x00,             # ANCOUNT
        0x00, 0x00,             # NSCOUNT
        0x00, 0x00,             # ARCOUNT
        # Question: google.com
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  # "google"
        0x03, 0x63, 0x6f, 0x6d,                      # "com"
        0x00,                                         # null terminator
        0x00, 0x01,             # QTYPE (A)
        0x00, 0x01              # QCLASS (IN)
    )
    
    Write-Host "Sending query ($($query.Length) bytes) to ${serverIP}:${serverPort}"
    Write-Host "Query (hex): $([BitConverter]::ToString($query))"
    
    # Send query
    $sent = $udpClient.Send($query, $query.Length, $serverIP, $serverPort)
    Write-Host "Sent: $sent bytes"
    
    # Receive response
    $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $response = $udpClient.Receive([ref]$remoteEP)
    
    Write-Host "`n Received response from $($remoteEP.Address):$($remoteEP.Port)"
    Write-Host "Response ($($response.Length) bytes): $([BitConverter]::ToString($response))"
    
    # Parse response header
    if ($response.Length -ge 12) {
        $id = [BitConverter]::ToUInt16($response[1..0], 0)
        $flags = [BitConverter]::ToUInt16($response[3..2], 0)
        $qdcount = [BitConverter]::ToUInt16($response[5..4], 0)
        $ancount = [BitConverter]::ToUInt16($response[7..6], 0)
        
        Write-Host "`nParsed Response:"
        Write-Host "  ID: $id"
        Write-Host "  Flags: 0x$($flags.ToString('X4'))"
        Write-Host "  Questions: $qdcount"
        Write-Host "  Answers: $ancount"
        
        if ($ancount -gt 0) {
            Write-Host "`n Server is responding with answers!"
        } else {
            Write-Host "`n Server responded but with no answers"
        }
    }
    
} catch {
    Write-Host " Error: $_"
} finally {
    $udpClient.Close()
}