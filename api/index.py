<!DOCTYPE html>
<html>
<head>
    <title>SecMate Enterprise</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f7fa;
        }

        h1 {
            margin-bottom: 5px;
        }

        .card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }

        input, select, textarea, button {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            margin-top: 8px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 6px;
        }

        button {
            cursor: pointer;
            font-weight: bold;
        }

        pre {
            background: #111;
            color: white;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
        }
    </style>
</head>

<body>

<div class="card">

    <h1>🛡️ SecMate Enterprise</h1>
    <p>AI-Assisted Security Assessment Platform</p>

    <label>Target</label>
    <input id="target" value="demo-app">

    <label>Workflow</label>
    <select id="workflow">
        <option>VAPT Security Analysis</option>
        <option>Red Team-Blue Team Assessment</option>
        <option>Combined Security Assessment</option>
    </select>

    <label>Intensity</label>
    <select id="intensity">
        <option>Basic</option>
        <option>Standard</option>
        <option>Advanced</option>
    </select>

    <label>Evidence / Context</label>
    <textarea id="evidence" rows="5">Example application contains a possible SQL injection input and weak authentication configuration.</textarea>

    <button onclick="runAssessment()">Run Assessment</button>

    <h3>Result</h3>
    <pre id="result">Waiting for assessment...</pre>

</div>

<script>
async function runAssessment() {

    const result = document.getElementById("result");

    result.textContent = "Running assessment...";

    const data = {
        target: document.getElementById("target").value,
        workflow: document.getElementById("workflow").value,
        intensity: document.getElementById("intensity").value,
        evidence: document.getElementById("evidence").value
    };

    try {

        const response = await fetch("/api", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        const output = await response.json();

        result.textContent = JSON.stringify(output, null, 2);

    } catch (error) {

        result.textContent = "Error: " + error.message;

    }
}
</script>

</body>
</html>
