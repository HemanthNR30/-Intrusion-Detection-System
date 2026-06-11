import { useState, useEffect } from "react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Legend
} from "recharts";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

const BACKEND = "http://localhost:3001";

const SEVERITY_COLORS = {
  HIGH: "#E24B4A",
  MEDIUM: "#F5A623",
  LOW: "#F8E71C",
  NONE: "#1D9E75"
};

const CHART_COLORS = ["#E24B4A", "#F5A623", "#4A90E2", "#7ED321", "#9B59B6", "#1ABC9C", "#E67E22"];

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ total_flows: 0, total_attacks: 0, attack_types: {} });
  const [connected, setConnected] = useState(false);
  const [trafficData, setTrafficData] = useState([]);
  const [verifiedAlerts, setVerifiedAlerts] = useState({});
  const [decryptedAlerts, setDecryptedAlerts] = useState({});
  const [filter, setFilter] = useState("ALL");
  const [showDecryptModal, setShowDecryptModal] = useState(false);
  const [decryptKeyInput, setDecryptKeyInput] = useState("");
  const [pendingDecryptId, setPendingDecryptId] = useState(null);
  const [decryptError, setDecryptError] = useState("");
  const [aiPanel, setAiPanel] = useState(null);
  const [aiMessages, setAiMessages] = useState([]);
  const [aiInput, setAiInput] = useState("");
  const [aiLoading, setAiLoading] = useState(false);

  const playAlertSound = () => {
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const o1 = audioCtx.createOscillator();
      const g1 = audioCtx.createGain();
      o1.connect(g1); g1.connect(audioCtx.destination);
      o1.frequency.value = 880; o1.type = "square";
      g1.gain.setValueAtTime(0.3, audioCtx.currentTime);
      g1.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.3);
      o1.start(audioCtx.currentTime); o1.stop(audioCtx.currentTime + 0.3);
      const o2 = audioCtx.createOscillator();
      const g2 = audioCtx.createGain();
      o2.connect(g2); g2.connect(audioCtx.destination);
      o2.frequency.value = 660; o2.type = "square";
      g2.gain.setValueAtTime(0.3, audioCtx.currentTime + 0.35);
      g2.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.65);
      o2.start(audioCtx.currentTime + 0.35); o2.stop(audioCtx.currentTime + 0.65);
    } catch (e) { console.log("Audio not available"); }
  };

  const verifyAlert = async (id) => {
    try {
      const res = await fetch(`${BACKEND}/alerts/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
      });
      const data = await res.json();
      setVerifiedAlerts(prev => ({ ...prev, [id]: data.verified }));
    } catch (err) {
      console.error("Verification failed", err);
    }
  };

  const openDecryptModal = (id) => {
    setPendingDecryptId(id);
    setDecryptKeyInput("");
    setDecryptError("");
    setShowDecryptModal(true);
  };

  const submitDecrypt = async () => {
    if (!decryptKeyInput.trim()) {
      setDecryptError("Please enter the secret key");
      return;
    }
    try {
      const res = await fetch(`${BACKEND}/alerts/decrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: pendingDecryptId, key: decryptKeyInput })
      });
      const data = await res.json();
      if (data.success) {
        setDecryptedAlerts(prev => ({ ...prev, [pendingDecryptId]: data.decrypted }));
        setShowDecryptModal(false);
        setDecryptError("");
      } else {
        setDecryptError("❌ Wrong key — access denied");
      }
    } catch (err) {
      setDecryptError("Error: " + err.message);
    }
  };

  const openAiPanel = async (alert) => {
    setAiPanel(alert);
    setAiMessages([]);
    setAiLoading(true);
    try {
      const res = await fetch(`${BACKEND}/ai/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attack_type: alert.prediction,
          confidence: alert.confidence,
          severity: alert.severity
        })
      });
      const data = await res.json();
      if (data.success) {
        setAiMessages([{ role: "ai", text: data.response }]);
      } else {
        setAiMessages([{ role: "ai", text: "Failed to analyze attack. Check your API key." }]);
      }
    } catch (err) {
      setAiMessages([{ role: "ai", text: "Failed to connect to AI analyst." }]);
    }
    setAiLoading(false);
  };

  const sendAiMessage = async () => {
    if (!aiInput.trim() || !aiPanel) return;
    const userMsg = aiInput.trim();
    setAiInput("");
    setAiMessages(prev => [...prev, { role: "user", text: userMsg }]);
    setAiLoading(true);
    try {
      const res = await fetch(`${BACKEND}/ai/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attack_type: aiPanel.prediction,
          confidence: aiPanel.confidence,
          severity: aiPanel.severity,
          question: userMsg
        })
      });
      const data = await res.json();
      if (data.success) {
        setAiMessages(prev => [...prev, { role: "ai", text: data.response }]);
      } else {
        setAiMessages(prev => [...prev, { role: "ai", text: "Error getting response." }]);
      }
    } catch (err) {
      setAiMessages(prev => [...prev, { role: "ai", text: "Connection error." }]);
    }
    setAiLoading(false);
  };

  const downloadPDF = () => {
    try {
      const doc = new jsPDF();
      doc.setFontSize(20);
      doc.setTextColor(40, 40, 40);
      doc.text("AI Network Intrusion Detection System", 14, 20);
      doc.setFontSize(11);
      doc.setTextColor(100, 100, 100);
      doc.text("Incident Report — Generated: " + new Date().toLocaleString(), 14, 30);
      doc.setDrawColor(200, 200, 200);
      doc.line(14, 34, 196, 34);
      doc.setFontSize(13);
      doc.setTextColor(40, 40, 40);
      doc.text("Summary Statistics", 14, 44);
      doc.setFontSize(11);
      doc.setTextColor(60, 60, 60);
      doc.text(`Total Flows Monitored:  ${stats.total_flows.toLocaleString()}`, 14, 54);
      doc.text(`Total Attacks Detected: ${stats.total_attacks.toLocaleString()}`, 14, 62);
      doc.text(`Attack Rate:            ${attackRate}%`, 14, 70);
      doc.text(`Unique Attack Types:    ${Object.keys(stats.attack_types || {}).length}`, 14, 78);
      doc.setFontSize(13);
      doc.setTextColor(40, 40, 40);
      doc.text("Attack Type Breakdown", 14, 94);
      const attackRows = Object.entries(stats.attack_types || {}).map(([type, count]) => [
        type, count, ((count / stats.total_attacks) * 100).toFixed(1) + "%"
      ]);
      autoTable(doc, {
        startY: 100,
        head: [["Attack Type", "Count", "Percentage"]],
        body: attackRows,
        headStyles: { fillColor: [226, 75, 74], textColor: 255 },
        alternateRowStyles: { fillColor: [245, 245, 245] },
        styles: { fontSize: 10 }
      });
      const finalY = doc.lastAutoTable.finalY + 14;
      doc.setFontSize(13);
      doc.setTextColor(40, 40, 40);
      doc.text("Recent Alerts", 14, finalY);
      const alertRows = alerts.slice(0, 50).map((alert) => [
        new Date(alert.timestamp).toLocaleString(),
        alert.prediction,
        alert.confidence + "%",
        alert.severity,
        alert.hash ? alert.hash.slice(0, 20) + "..." : "N/A"
      ]);
      autoTable(doc, {
        startY: finalY + 6,
        head: [["Timestamp", "Attack Type", "Confidence", "Severity", "SHA-256"]],
        body: alertRows,
        headStyles: { fillColor: [30, 30, 40], textColor: 255 },
        alternateRowStyles: { fillColor: [245, 245, 245] },
        styles: { fontSize: 9 }
      });
      const pageCount = doc.internal.getNumberOfPages();
      for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(9);
        doc.setTextColor(150, 150, 150);
        doc.text(`NIDS Report — Page ${i} of ${pageCount} — Confidential`, 14, doc.internal.pageSize.height - 10);
      }
      doc.save(`NIDS_Report_${new Date().toISOString().slice(0, 10)}.pdf`);
    } catch (e) {
      console.error("PDF error:", e);
    }
  };

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const [alertsRes, statsRes] = await Promise.all([
          fetch(`${BACKEND}/alerts`),
          fetch(`${BACKEND}/stats`)
        ]);
        const alertsData = await alertsRes.json();
        const statsData = await statsRes.json();
        setAlerts((prevAlerts) => {
          const newAlerts = alertsData.reverse();
          const prevIds = new Set(prevAlerts.map((a) => a.id));
          const newHigh = newAlerts.filter(a => !prevIds.has(a.id) && a.severity === "HIGH");
          if (newHigh.length > 0) playAlertSound();
          return newAlerts.slice(0, 100);
        });
        setStats(statsData);
        setConnected(true);
        setTrafficData((prev) => {
          const newPoint = {
            time: new Date().toLocaleTimeString(),
            flows: statsData.total_flows,
            attacks: statsData.total_attacks
          };
          return [...prev, newPoint].slice(-20);
        });
      } catch (err) {
        setConnected(false);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const pieData = Object.entries(stats.attack_types || {}).map(([name, value]) => ({ name, value }));
  const attackRate = stats.total_flows > 0
    ? ((stats.total_attacks / stats.total_flows) * 100).toFixed(1) : 0;
  const filteredAlerts = filter === "ALL" ? alerts : alerts.filter(a => a.severity === filter);

  return (
    <div style={{ background: "#0D1117", minHeight: "100vh", color: "#E6EDF3", fontFamily: "monospace", padding: "20px" }}>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: "bold", color: "#58A6FF", margin: 0 }}>
            🛡️ AI Network Intrusion Detection System
          </h1>
          <p style={{ color: "#8B949E", fontSize: "12px", margin: "4px 0 0" }}>
            Real-time threat monitoring · SHA-256 secured · AES-256 encrypted · AI powered
          </p>
        </div>
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <button onClick={downloadPDF} disabled={alerts.length === 0} style={{
            padding: "6px 16px", borderRadius: "20px", fontSize: "12px", fontWeight: "bold",
            cursor: alerts.length === 0 ? "not-allowed" : "pointer",
            background: alerts.length === 0 ? "#30363D" : "#1D9E7520",
            color: alerts.length === 0 ? "#8B949E" : "#1D9E75",
            border: `1px solid ${alerts.length === 0 ? "#30363D" : "#1D9E75"}`
          }}>
            📄 Download Report
          </button>
          <div style={{
            padding: "6px 14px", borderRadius: "20px", fontSize: "12px", fontWeight: "bold",
            background: connected ? "#1D9E7520" : "#E24B4A20",
            color: connected ? "#1D9E75" : "#E24B4A",
            border: `1px solid ${connected ? "#1D9E75" : "#E24B4A"}`
          }}>
            {connected ? "🟢 LIVE" : "🔴 DISCONNECTED"}
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "24px" }}>
        {[
          { label: "Total Flows", value: stats.total_flows.toLocaleString(), color: "#58A6FF" },
          { label: "Attacks Detected", value: stats.total_attacks.toLocaleString(), color: "#E24B4A" },
          { label: "Attack Rate", value: `${attackRate}%`, color: "#F5A623" },
          { label: "Attack Types", value: Object.keys(stats.attack_types || {}).length, color: "#BC8CFF" }
        ].map((card) => (
          <div key={card.label} style={{
            background: "#161B22", border: "1px solid #30363D", borderRadius: "10px", padding: "16px"
          }}>
            <p style={{ color: "#8B949E", fontSize: "11px", margin: "0 0 8px", textTransform: "uppercase" }}>{card.label}</p>
            <p style={{ color: card.color, fontSize: "28px", fontWeight: "bold", margin: 0 }}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "24px" }}>
        <div style={{ background: "#161B22", border: "1px solid #30363D", borderRadius: "10px", padding: "16px" }}>
          <h3 style={{ margin: "0 0 16px", fontSize: "13px", color: "#8B949E" }}>TRAFFIC OVER TIME</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#30363D" />
              <XAxis dataKey="time" tick={{ fill: "#8B949E", fontSize: 10 }} />
              <YAxis tick={{ fill: "#8B949E", fontSize: 10 }} />
              <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", color: "#E6EDF3" }} />
              <Legend />
              <Line type="monotone" dataKey="flows" stroke="#58A6FF" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="attacks" stroke="#E24B4A" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div style={{ background: "#161B22", border: "1px solid #30363D", borderRadius: "10px", padding: "16px" }}>
          <h3 style={{ margin: "0 0 16px", fontSize: "13px", color: "#8B949E" }}>ATTACK TYPE BREAKDOWN</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {pieData.map((_, index) => (
                    <Cell key={index} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", color: "#E6EDF3" }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center", color: "#8B949E" }}>
              Waiting for attacks...
            </div>
          )}
        </div>
      </div>

      {/* Alert Feed */}
      <div style={{ background: "#161B22", border: "1px solid #30363D", borderRadius: "10px", padding: "16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
          <h3 style={{ margin: 0, fontSize: "13px", color: "#8B949E" }}>LIVE ALERT FEED</h3>
          <div style={{ display: "flex", gap: "6px" }}>
            {["ALL", "HIGH", "MEDIUM", "LOW"].map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{
                padding: "3px 10px", borderRadius: "20px", fontSize: "11px",
                fontWeight: "bold", cursor: "pointer", border: "1px solid",
                background: filter === f ? `${SEVERITY_COLORS[f] || "#58A6FF"}30` : "transparent",
                color: filter === f ? (SEVERITY_COLORS[f] || "#58A6FF") : "#8B949E",
                borderColor: filter === f ? (SEVERITY_COLORS[f] || "#58A6FF") : "#30363D"
              }}>{f}</button>
            ))}
          </div>
          <span style={{ fontSize: "11px", color: "#8B949E" }}>{filteredAlerts.length} alerts</span>
        </div>

        <div style={{ maxHeight: "400px", overflowY: "auto" }}>
          {filteredAlerts.length === 0 ? (
            <p style={{ color: "#8B949E", textAlign: "center", padding: "40px 0" }}>
              Monitoring traffic... no attacks yet
            </p>
          ) : (
            filteredAlerts.map((alert) => (
              <div key={alert.id} style={{
                padding: "10px 12px", marginBottom: "6px",
                background: "#0D1117", borderRadius: "6px",
                borderLeft: `3px solid ${SEVERITY_COLORS[alert.severity] || "#E24B4A"}`
              }}>
                {/* Main row */}
                <div style={{ display: "grid", gridTemplateColumns: "140px 1fr 80px 80px 80px 80px", gap: "12px", alignItems: "center" }}>
                  <span style={{ color: "#8B949E", fontSize: "11px" }}>
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                  <span style={{ color: "#E24B4A", fontSize: "12px", fontWeight: "bold" }}>
                    {alert.prediction}
                  </span>
                  <span style={{ color: "#8B949E", fontSize: "11px" }}>{alert.confidence}%</span>
                  <span style={{
                    fontSize: "10px", fontWeight: "bold", textAlign: "center",
                    padding: "2px 6px", borderRadius: "4px",
                    background: `${SEVERITY_COLORS[alert.severity]}20`,
                    color: SEVERITY_COLORS[alert.severity]
                  }}>{alert.severity}</span>
                  <span style={{ color: "#8B949E", fontSize: "11px" }}>{alert.actual}</span>
                  <div style={{ display: "flex", gap: "4px" }}>
                    <button onClick={() => verifyAlert(alert.id)} style={{
                      background: "transparent", border: "none", cursor: "pointer", fontSize: "13px"
                    }} title="Verify SHA-256 integrity">🔐</button>
                    <button onClick={() => openDecryptModal(alert.id)} style={{
                      background: "transparent", border: "none", cursor: "pointer", fontSize: "13px"
                    }} title="Decrypt with secret key">🔓</button>
                    <button onClick={() => openAiPanel(alert)} style={{
                      background: "transparent", border: "none", cursor: "pointer", fontSize: "13px"
                    }} title="Ask AI for remediation advice">🤖</button>
                  </div>
                </div>

                {/* SHA-256 row */}
                {alert.hash && (
                  <div style={{
                    marginTop: "6px", padding: "4px 8px",
                    background: "#161B22", borderRadius: "4px",
                    display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap"
                  }}>
                    <span style={{ color: "#8B949E", fontSize: "10px" }}>SHA-256:</span>
                    <span style={{ color: "#3FB950", fontSize: "10px", fontFamily: "monospace", letterSpacing: "0.05em" }}>
                      {alert.hash}
                    </span>
                    {verifiedAlerts[alert.id] !== undefined && (
                      <span style={{
                        fontSize: "10px", fontWeight: "bold",
                        color: verifiedAlerts[alert.id] ? "#1D9E75" : "#E24B4A",
                        marginLeft: "auto"
                      }}>
                        {verifiedAlerts[alert.id] ? "✅ VERIFIED — not tampered" : "❌ TAMPERED — hash mismatch"}
                      </span>
                    )}
                  </div>
                )}

                {/* AES encrypted row */}
                {alert.encrypted && (
                  <div style={{
                    marginTop: "4px", padding: "4px 8px",
                    background: "#161B22", borderRadius: "4px",
                    display: "flex", alignItems: "center", gap: "8px"
                  }}>
                    <span style={{ color: "#8B949E", fontSize: "10px" }}>AES-256:</span>
                    <span style={{
                      color: "#BC8CFF", fontSize: "10px", fontFamily: "monospace",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      maxWidth: "500px"
                    }}>
                      {alert.encrypted.slice(0, 80)}...
                    </span>
                  </div>
                )}

                {/* Decrypted panel */}
                {decryptedAlerts[alert.id] && (
                  <div style={{
                    marginTop: "6px", padding: "10px 12px",
                    background: "#0D2818", borderRadius: "4px",
                    border: "1px solid #1D9E75"
                  }}>
                    <p style={{ color: "#1D9E75", fontSize: "10px", fontWeight: "bold", margin: "0 0 8px" }}>
                      🔓 DECRYPTED DATA
                    </p>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "6px" }}>
                      {Object.entries(decryptedAlerts[alert.id]).map(([key, value]) => (
                        key !== 'id' && (
                          <div key={key}>
                            <span style={{ color: "#8B949E", fontSize: "10px" }}>{key}: </span>
                            <span style={{ color: "#E6EDF3", fontSize: "10px", fontFamily: "monospace" }}>
                              {String(value)}
                            </span>
                          </div>
                        )
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Decrypt Modal */}
      {showDecryptModal && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.8)", display: "flex",
          alignItems: "center", justifyContent: "center", zIndex: 1000
        }}>
          <div style={{
            background: "#161B22", border: "1px solid #30363D",
            borderRadius: "12px", padding: "24px", width: "400px"
          }}>
            <h3 style={{ color: "#E6EDF3", fontSize: "15px", margin: "0 0 8px" }}>
              🔓 Decrypt Alert
            </h3>
            <p style={{ color: "#8B949E", fontSize: "12px", margin: "0 0 16px", lineHeight: "1.6" }}>
              Enter the AES-256 secret key to decrypt this alert's encrypted data.
              Wrong key = access denied.
            </p>
            <input
              type="password"
              placeholder="Enter secret key..."
              value={decryptKeyInput}
              onChange={(e) => setDecryptKeyInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submitDecrypt()}
              style={{
                width: "100%", padding: "10px 12px",
                background: "#0D1117", border: "1px solid #30363D",
                borderRadius: "6px", color: "#E6EDF3",
                fontSize: "13px", fontFamily: "monospace",
                outline: "none", marginBottom: "8px",
                boxSizing: "border-box"
              }}
            />
            {decryptError && (
              <p style={{ color: "#E24B4A", fontSize: "11px", margin: "0 0 8px" }}>
                {decryptError}
              </p>
            )}
            <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
              <button onClick={submitDecrypt} style={{
                flex: 1, padding: "8px", borderRadius: "6px",
                background: "#1D9E7520", color: "#1D9E75",
                border: "1px solid #1D9E75", cursor: "pointer",
                fontSize: "12px", fontWeight: "bold"
              }}>
                🔓 Decrypt
              </button>
              <button onClick={() => setShowDecryptModal(false)} style={{
                flex: 1, padding: "8px", borderRadius: "6px",
                background: "#E24B4A20", color: "#E24B4A",
                border: "1px solid #E24B4A", cursor: "pointer",
                fontSize: "12px", fontWeight: "bold"
              }}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Analyst Panel */}
      {aiPanel && (
        <div style={{
          position: "fixed", top: 0, right: 0, bottom: 0, width: "420px",
          background: "#161B22", borderLeft: "1px solid #30363D",
          display: "flex", flexDirection: "column", zIndex: 1000
        }}>
          <div style={{
            padding: "16px", borderBottom: "1px solid #30363D",
            display: "flex", justifyContent: "space-between", alignItems: "center"
          }}>
            <div>
              <p style={{ color: "#58A6FF", fontSize: "13px", fontWeight: "bold", margin: 0 }}>
                🤖 AI Security Analyst
              </p>
              <p style={{ color: "#8B949E", fontSize: "11px", margin: "2px 0 0" }}>
                Analyzing: {aiPanel.prediction} ({aiPanel.confidence}% confidence)
              </p>
            </div>
            <button onClick={() => setAiPanel(null)} style={{
              background: "transparent", border: "none", color: "#8B949E",
              cursor: "pointer", fontSize: "18px"
            }}>✕</button>
          </div>

          {/* Attack summary */}
          <div style={{
            margin: "12px 16px", padding: "10px 12px",
            background: `${SEVERITY_COLORS[aiPanel.severity]}15`,
            border: `1px solid ${SEVERITY_COLORS[aiPanel.severity]}40`,
            borderRadius: "8px"
          }}>
            <div style={{ display: "flex", gap: "16px" }}>
              <div>
                <p style={{ color: "#8B949E", fontSize: "10px", margin: "0 0 2px" }}>ATTACK</p>
                <p style={{ color: "#E24B4A", fontSize: "12px", fontWeight: "bold", margin: 0 }}>{aiPanel.prediction}</p>
              </div>
              <div>
                <p style={{ color: "#8B949E", fontSize: "10px", margin: "0 0 2px" }}>SEVERITY</p>
                <p style={{ color: SEVERITY_COLORS[aiPanel.severity], fontSize: "12px", fontWeight: "bold", margin: 0 }}>{aiPanel.severity}</p>
              </div>
              <div>
                <p style={{ color: "#8B949E", fontSize: "10px", margin: "0 0 2px" }}>CONFIDENCE</p>
                <p style={{ color: "#58A6FF", fontSize: "12px", fontWeight: "bold", margin: 0 }}>{aiPanel.confidence}%</p>
              </div>
            </div>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: "auto", padding: "0 16px" }}>
            {aiLoading && aiMessages.length === 0 && (
              <div style={{ color: "#8B949E", fontSize: "12px", padding: "20px 0", textAlign: "center" }}>
                🤖 Analyzing attack...
              </div>
            )}
            {aiMessages.map((msg, i) => (
              <div key={i} style={{
                marginBottom: "12px",
                display: "flex",
                justifyContent: msg.role === "user" ? "flex-end" : "flex-start"
              }}>
                <div style={{
                  maxWidth: "85%", padding: "10px 12px", borderRadius: "8px",
                  background: msg.role === "user" ? "#1D4ED820" : "#0D2818",
                  border: `1px solid ${msg.role === "user" ? "#1D4ED840" : "#1D9E7540"}`,
                  color: "#E6EDF3", fontSize: "12px", lineHeight: "1.6"
                }}>
                  {msg.role === "ai" && (
                    <p style={{ color: "#1D9E75", fontSize: "10px", fontWeight: "bold", margin: "0 0 6px" }}>
                      🤖 AI ANALYST
                    </p>
                  )}
                  {msg.text}
                </div>
              </div>
            ))}
            {aiLoading && aiMessages.length > 0 && (
              <div style={{ color: "#8B949E", fontSize: "11px", padding: "8px 0" }}>
                🤖 Thinking...
              </div>
            )}
          </div>

          {/* Input */}
          <div style={{ padding: "16px", borderTop: "1px solid #30363D" }}>
            <p style={{ color: "#8B949E", fontSize: "10px", margin: "0 0 8px" }}>
              Ask about remediation, firewall rules, attack details...
            </p>
            <div style={{ display: "flex", gap: "8px" }}>
              <input
                type="text"
                placeholder="e.g. How do I block this attack?"
                value={aiInput}
                onChange={(e) => setAiInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && sendAiMessage()}
                style={{
                  flex: 1, padding: "8px 12px",
                  background: "#0D1117", border: "1px solid #30363D",
                  borderRadius: "6px", color: "#E6EDF3",
                  fontSize: "12px", outline: "none"
                }}
              />
              <button onClick={sendAiMessage} disabled={aiLoading} style={{
                padding: "8px 14px", borderRadius: "6px",
                background: "#58A6FF20", color: "#58A6FF",
                border: "1px solid #58A6FF", cursor: "pointer",
                fontSize: "12px", fontWeight: "bold"
              }}>
                Send
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}