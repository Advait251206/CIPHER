/**
 * CIPHER Extension Verification Script via Chrome DevTools Protocol (CDP).
 * Connects to the loaded unpacked extension background service worker,
 * triggers threat checks, and captures live console logs.
 */

const http = require('http');
const path = require('path');
const WebSocket = require(path.resolve(__dirname, '../../../frontend/node_modules/ws'));

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

async function main() {
  console.log("=== CIPHER BROWSER EXTENSION VERIFICATION ===");
  console.log("Querying Chrome DevTools targets on http://127.0.0.1:9333/json...");

  let targets = [];
  try {
    targets = await httpGetJson("http://127.0.0.1:9333/json");
  } catch (err) {
    console.error("Failed to connect to Chrome CDP:", err.message);
    process.exit(1);
  }

  console.log(`Discovered ${targets.length} browser targets:`);
  let swTarget = null;
  for (const t of targets) {
    console.log(`  - [${t.type}] ${t.title || "(no title)"}: ${t.url}`);
    if (t.type === "service_worker" && t.url.includes("chrome-extension://")) {
      swTarget = t;
    }
  }

  if (!swTarget) {
    console.log("No extension service worker found. Searching other extension targets...");
    swTarget = targets.find(t => t.url.includes("chrome-extension://"));
  }

  if (!swTarget || !swTarget.webSocketDebuggerUrl) {
    console.error("Could not find WebSocket debugger URL for extension.");
    process.exit(1);
  }

  console.log(`\nConnecting to Service Worker WebSocket: ${swTarget.webSocketDebuggerUrl}`);
  const ws = new WebSocket(swTarget.webSocketDebuggerUrl);

  const consoleLogs = [];

  ws.on('open', () => {
    console.log("Connected to Extension Service Worker DevTools.");
    ws.send(JSON.stringify({ id: 1, method: "Runtime.enable" }));
    ws.send(JSON.stringify({ id: 2, method: "Log.enable" }));

    setTimeout(() => {
      console.log("\nEvaluating test CHECK_URL against local backend...");
      const evalPayload = {
        id: 3,
        method: "Runtime.evaluate",
        params: {
          expression: `
            inspectUrl("http://testsafebrowsing.appspot.com/s/phishing.html").then(res => {
              console.log("[CIPHER_EXT_TEST] Phishing URL check result:", JSON.stringify(res));
            });
            inspectUrl("https://example.com").then(res => {
              console.log("[CIPHER_EXT_TEST] Benign URL check result:", JSON.stringify(res));
            });
          `
        }
      };
      ws.send(JSON.stringify(evalPayload));
    }, 1000);

    setTimeout(() => {
      console.log("\nEvaluating settings retrieval...");
      ws.send(JSON.stringify({
        id: 4,
        method: "Runtime.evaluate",
        params: {
          expression: `
            getSettings().then(s => {
              console.log("[CIPHER_EXT_TEST] Active Settings:", JSON.stringify(s));
            });
          `
        }
      }));
    }, 2000);

    setTimeout(() => {
      console.log("\nFinished collecting extension logs. Closing debugger session.");
      ws.close();
    }, 4000);
  });

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (data.method === "Runtime.consoleAPICalled") {
        const text = data.params.args.map(a => a.value || JSON.stringify(a)).join(" ");
        console.log(`[SW CONSOLE ${data.params.type.toUpperCase()}] ${text}`);
        consoleLogs.push(text);
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    console.log("WebSocket connection closed.");
    console.log(`Collected ${consoleLogs.length} console log entries from extension service worker.`);
    process.exit(0);
  });
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
