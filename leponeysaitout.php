<?php
// Inclusion de la config et connexion MySQL
require_once 'configuration.php';

$conn = new mysqli(HOSTNAME, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Erreur de connexion à la base : ' . $conn->connect_error]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['ajax'])) {
    header('Content-Type: application/json');

    $PASSWORD = 'poney';  // mot de passe d'accès
    $data = json_decode(file_get_contents('php://input'), true);

    if (!isset($data['auth']) || $data['auth'] !== $PASSWORD) {
        echo json_encode(['error' => 'Mot de passe invalide.']);
        exit;
    }

    $query = isset($data['query']) ? trim($data['query']) : '';

    if (empty($query)) {
        echo json_encode(['error' => 'Aucune requête SQL fournie.']);
        exit;
    }

    // Exécution sécurisée (attention, pas de protection contre injections SQL ici)
    $result = $conn->query($query);
    if ($result === false) {
        echo json_encode(['error' => 'Erreur SQL : ' . $conn->error]);
        exit;
    }

    // Si c'est un SELECT, on récupère les résultats
    if ($result instanceof mysqli_result) {
        $rows = [];
        while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
        }
        $result->free();
        echo json_encode(['query' => $query, 'result' => $rows]);
    } else {
        // Pour les requêtes UPDATE/INSERT/DELETE on renvoie le nombre de lignes affectées
        echo json_encode(['query' => $query, 'affected_rows' => $conn->affected_rows]);
    }
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>💻 Mini Console MySQL</title>
    <style>
        body { background:#1e1e1e; color:#d0d0d0; font-family:monospace; padding:20px; }
        textarea, input[type=password] {
            width: 100%; padding:6px; background:#333; color:#0f0;
            border:1px solid #555; font-size:16px; font-family: monospace;
        }
        button {
            padding:6px 12px; background:#444; color:#fff;
            border:1px solid #777; cursor:pointer;
            margin-top: 8px;
        }
        .block {
            background:#2a2a2a; margin-top:10px; padding:10px;
            border-left:4px solid #0af;
            white-space: pre-wrap;
        }
        .error { color: #f33; font-weight: bold; }
    </style>
</head>
<body>
    <h2>💻 Mini Console MySQL</h2>

    <div id="auth">
        <input type="password" id="pw" placeholder="Mot de passe">
        <button onclick="login()">Valider</button>
    </div>

    <div id="console" style="display:none;">
        <textarea id="query" rows="6" placeholder="Entrez votre requête SQL ici..."></textarea>
        <button onclick="sendQuery()">Exécuter la requête</button>
        <div id="results"></div>
    </div>

<script>
    let password = '';

    function login() {
        password = document.getElementById('pw').value;
        if (!password) {
            alert('Entrez le mot de passe');
            return;
        }
        // On test juste le mot de passe côté client, on pourra tenter une requête dummy côté serveur plus tard si besoin
        document.getElementById('auth').style.display = 'none';
        document.getElementById('console').style.display = 'block';
    }

    function sendQuery() {
        const query = document.getElementById('query').value.trim();
        if (!query) {
            alert('Entrez une requête SQL');
            return;
        }

        fetch('?ajax=1', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ auth: password, query: query })
        })
        .then(res => res.json())
        .then(data => {
            const resultsDiv = document.getElementById('results');
            if (data.error) {
                resultsDiv.innerHTML = '<div class="block error">' + data.error + '</div>';
            } else if (data.result) {
                // Résultat SELECT
                if (data.result.length === 0) {
                    resultsDiv.innerHTML = '<div class="block">(Aucun résultat)</div>';
                } else {
                    let html = '<div class="block">';
                    // Affichage en tableau simple
                    html += '<table border="1" cellpadding="4" cellspacing="0" style="border-collapse: collapse; color:#0f0; background:#111;">';
                    // Header
                    html += '<tr>';
                    for (let key in data.result[0]) {
                        html += '<th>' + key + '</th>';
                    }
                    html += '</tr>';
                    // Lignes
                    data.result.forEach(row => {
                        html += '<tr>';
                        for (let key in row) {
                            html += '<td>' + row[key] + '</td>';
                        }
                        html += '</tr>';
                    });
                    html += '</table></div>';
                    resultsDiv.innerHTML = html;
                }
            } else if (data.affected_rows !== undefined) {
                resultsDiv.innerHTML = '<div class="block">Requête exécutée. Lignes affectées : ' + data.affected_rows + '</div>';
            } else {
                resultsDiv.innerHTML = '<div class="block">Requête exécutée.</div>';
            }
        })
        .catch(err => {
            document.getElementById('results').innerHTML = '<div class="block error">Erreur : ' + err.message + '</div>';
        });
    }
</script>

</body>
</html>
