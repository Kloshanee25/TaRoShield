async function scanMessage() {
  const text = document.getElementById("smsText").value.trim();
  if (!text) return;

  const resultBox = document.getElementById("resultBox");
  const title = document.getElementById("resultTitle");
  const desc = document.getElementById("resultText");

  // Reset classes
  resultBox.classList.remove("safe", "danger");
  resultBox.classList.add("loading");

  title.innerText = "Scanning...";
  desc.innerText = "Analyzing message for smishing patterns...";

  try {
    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text })  // ✅ Fixed: "text" not "message"
    });

    const data = await response.json();
    resultBox.classList.remove("loading");

    const riskPercent = data.risk !== null ? Math.round(data.risk * 100) : null;

    if (data.label === "phishing") {   // ✅ Fixed: "label" not "prediction", "phishing" not "smishing"
      resultBox.classList.add("danger");
      title.innerText = "⚠ Malicious (Smishing Detected)";
      desc.innerText = riskPercent !== null
        ? `This message is ${riskPercent}% likely to be a smishing attack. Avoid clicking any links or sharing personal information.`
        : "This message appears to be a smishing attempt. Avoid clicking links or sharing information.";
    } else {
      resultBox.classList.add("safe");
      title.innerText = "✔ Legitimate Message";
      desc.innerText = riskPercent !== null
        ? `This message is ${riskPercent}% likely to be safe. No smishing patterns detected.`
        : "This message appears to be safe.";
    }

  } catch (err) {
    resultBox.classList.remove("loading");
    resultBox.classList.add("danger");
    title.innerText = "⚠ Connection Error";
    desc.innerText = "Could not connect to the detection server. Make sure Flask is running: python app.py";
  }
}
